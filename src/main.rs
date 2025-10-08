use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use crossbeam_channel as channel;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use winit::event::Event;
use winit::event_loop::{ControlFlow, EventLoop, EventLoopBuilder, EventLoopProxy};

#[cfg(target_os = "macos")]
use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};

const PORT_START: u16 = 3000;
const PORT_END: u16 = 10000; // inclusive
const SCAN_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessInfo {
    pid: i32,
    ports: BTreeSet<u16>,
    name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProcessSnapshot {
    // pid -> info
    processes: HashMap<i32, ProcessInfo>,
}

impl ProcessSnapshot {
    fn count(&self) -> usize {
        self.processes.len()
    }
}

#[derive(Debug, Clone)]
enum AppEvent {
    UpdateSnapshot(ProcessSnapshot),
    MenuKillAll,
    MenuQuit,
    MenuKillPid(i32),
}

#[derive(Debug, Clone)]
enum MonitorCmd {
    RescanNow,
    Shutdown,
}

fn main() {

    // Build winit event loop with custom user events
    #[cfg(target_os = "macos")]
    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event()
        .with_activation_policy(ActivationPolicy::Accessory)
        .build()
        .unwrap();

    #[cfg(not(target_os = "macos"))]
    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event().build().unwrap();

    let proxy = event_loop.create_proxy();

    // Build tray icon with a visible red dot and initial menu
    let icon = make_red_dot_icon(18);
    let tray_menu = Menu::new();

    let mut tray = TrayIconBuilder::new()
        .with_icon(icon)
        .with_menu(Box::new(tray_menu))
        .with_tooltip(&format!(
            "No dev servers on ports {}-{}",
            PORT_START, PORT_END
        ))
        .with_title("0")
        .build()
        .expect("tray icon");

    // Crossbeam channel for monitor thread commands
    let (mon_tx, mon_rx) = channel::unbounded::<MonitorCmd>();

    // Shared state for mapping menu item IDs to actions/PIDs
    let menu_state = Arc::new(Mutex::new(MenuState::default()));

    // Spawn monitor thread which periodically scans and posts UI updates
    spawn_monitor(proxy.clone(), mon_rx);

    // Spawn a thread to receive menu events and send user events
    let menu_proxy = proxy.clone();
    let menu_state_for_thread = Arc::clone(&menu_state);
    thread::spawn(move || {
        let rx = MenuEvent::receiver();
        while let Ok(event) = rx.recv() {
            let mut guard = menu_state_for_thread.lock().ok();
            if let Some(state) = guard.as_mut() {
                if event.id == state.kill_all {
                    let _ = menu_proxy.send_event(AppEvent::MenuKillAll);
                    continue;
                }
                if event.id == state.quit {
                    let _ = menu_proxy.send_event(AppEvent::MenuQuit);
                    continue;
                }
                if let Some(&pid) = state.pid_by_id.get(&event.id) {
                    let _ = menu_proxy.send_event(AppEvent::MenuKillPid(pid));
                }
            }
        }
    });

    // Keep a cache of current snapshot for rebuilding menu and computing counts
    let mut current_snapshot = ProcessSnapshot::default();

    // Track last snapshot used for the menu to avoid unnecessary rebuilds while hovering
    let mut last_built_menu_snapshot: Option<ProcessSnapshot> = None;

    // Initial manual scan for immediate UI
    if let Ok(snap) = perform_scan() {
        current_snapshot = snap.clone();
        update_tray_ui(&mut tray, &snap);
        rebuild_dynamic_menu(&mut tray, &snap, &menu_state);
        last_built_menu_snapshot = Some(snap);
    }
    let _ = event_loop.run(move |event, elwt| {
        elwt.set_control_flow(ControlFlow::Wait);
        match event {
            Event::UserEvent(AppEvent::UpdateSnapshot(snap)) => {
                current_snapshot = snap.clone();
                update_tray_ui(&mut tray, &snap);
                if last_built_menu_snapshot.as_ref() != Some(&snap) {
                    rebuild_dynamic_menu(&mut tray, &snap, &menu_state);
                    last_built_menu_snapshot = Some(snap);
                }
            }
            Event::UserEvent(AppEvent::MenuKillAll) => {
                let self_pid = std::process::id() as i32;
                let pids: Vec<i32> = current_snapshot
                    .processes
                    .keys()
                    .filter(|&&pid| pid != self_pid)
                    .cloned()
                    .collect();
                let mut failures = 0usize;
                for pid in pids {
                    if let Err(e) = terminate_process(pid) {
                        eprintln!("Failed to kill {pid}: {e}");
                        failures += 1;
                    }
                }
                if failures == 0 {
                    let _ = tray.set_tooltip(Some("Killed all detected dev processes"));
                } else {
                    let _ = tray.set_tooltip(Some(&format!(
                        "Killed with {} failure(s) — check permissions",
                        failures
                    )));
                }
                let _ = mon_tx.send(MonitorCmd::RescanNow);
            }
            Event::UserEvent(AppEvent::MenuKillPid(pid)) => {
                if pid == std::process::id() as i32 {
                    let _ = tray.set_tooltip(Some("Skipping self process"));
                    return;
                }
                match terminate_process(pid) {
                    Ok(_) => { let _ = tray.set_tooltip(Some(&format!("Terminated PID {}", pid))); }
                    Err(e) => { let _ = tray.set_tooltip(Some(&format!(
                        "Failed to terminate PID {}: {}",
                        pid, e
                    ))); }
                };
                let _ = mon_tx.send(MonitorCmd::RescanNow);
            }
            Event::UserEvent(AppEvent::MenuQuit) => {
                let _ = mon_tx.send(MonitorCmd::Shutdown);
                elwt.exit();
            }
            _ => {}
        }
    });
}

fn make_red_dot_icon(size: u32) -> Icon {
    let w = size as usize;
    let h = size as usize;
    let mut rgba = vec![0u8; w * h * 4];
    let cx = (w as f32) / 2.0;
    let cy = (h as f32) / 2.0;
    let r = (w.min(h) as f32) * 0.35;
    for y in 0..h {
        for x in 0..w {
            let dx = x as f32 - cx + 0.5;
            let dy = y as f32 - cy + 0.5;
            let dist2 = dx * dx + dy * dy;
            let idx = (y * w + x) * 4;
            if dist2 <= r * r {
                rgba[idx] = 220;
                rgba[idx + 1] = 60;
                rgba[idx + 2] = 60;
                rgba[idx + 3] = 255;
            } else {
                rgba[idx + 3] = 0;
            }
        }
    }
    Icon::from_rgba(rgba, size, size).expect("red dot icon")
}

#[derive(Default)]
struct MenuState {
    kill_all: MenuId,
    quit: MenuId,
    pid_by_id: HashMap<MenuId, i32>,
}

fn spawn_monitor(proxy: EventLoopProxy<AppEvent>, rx: channel::Receiver<MonitorCmd>) {
    thread::spawn(move || {
        // Use a loop with timeout-based select to scan every 2s, or on demand.
        let mut last_scan = Instant::now() - SCAN_INTERVAL;
        loop {
            let time_since = Instant::now() - last_scan;
            let remaining = if time_since >= SCAN_INTERVAL {
                Duration::from_secs(0)
            } else {
                SCAN_INTERVAL - time_since
            };

            let scan_now = if remaining.is_zero() {
                true
            } else {
                match rx.recv_timeout(remaining) {
                    Ok(MonitorCmd::RescanNow) => true,
                    Ok(MonitorCmd::Shutdown) => break,
                    Err(channel::RecvTimeoutError::Timeout) => true,
                    Err(channel::RecvTimeoutError::Disconnected) => break,
                }
            };

            if scan_now {
                last_scan = Instant::now();
                match perform_scan() {
                    Ok(snap) => {
                        let _ = proxy.send_event(AppEvent::UpdateSnapshot(snap));
                    }
                    Err(e) => {
                        eprintln!("Scan error: {e:?}");
                        // Still send an empty snapshot to keep UI responsive
                        let _ = proxy.send_event(AppEvent::UpdateSnapshot(
                            ProcessSnapshot::default(),
                        ));
                    }
                }
            }
        }
    });
}

fn perform_scan() -> Result<ProcessSnapshot> {
    let mut pid_to_info: HashMap<i32, ProcessInfo> = HashMap::new();

    // Use lsof with port range for much faster scanning
    let cmd = format!("lsof -ti :{PORT_START}-{PORT_END} -sTCP:LISTEN 2>/dev/null");
    let output = Command::new("sh").arg("-lc").arg(&cmd).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pids: BTreeSet<i32> = stdout
        .lines()
        .filter_map(|line| i32::from_str(line.trim()).ok())
        .collect();

    // For each PID, find which specific ports it's listening on
    for &pid in &pids {
        let port_cmd = format!("lsof -Pan -p {pid} -iTCP -sTCP:LISTEN 2>/dev/null | awk '{{print $9}}' | grep -oE '[0-9]+$'");
        let port_output = Command::new("sh").arg("-lc").arg(&port_cmd).output()?;

        let ports: BTreeSet<u16> = String::from_utf8_lossy(&port_output.stdout)
            .lines()
            .filter_map(|line| u16::from_str(line.trim()).ok())
            .filter(|&p| p >= PORT_START && p <= PORT_END)
            .collect();

        if !ports.is_empty() {
            let name = process_name(pid).unwrap_or_else(|_| "?".to_string());
            pid_to_info.insert(pid, ProcessInfo { pid, ports, name });
        }
    }

    Ok(ProcessSnapshot { processes: pid_to_info })
}

fn process_name(pid: i32) -> Result<String> {
    let cmd = format!("ps -p {} -o comm=", pid);
    let out = Command::new("sh").arg("-lc").arg(&cmd).output()?;
    if !out.status.success() {
        return Err(anyhow!("ps failed for pid {}", pid));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(if s.is_empty() { "?".into() } else { s })
}

fn terminate_process(pid: i32) -> Result<()> {
    let npid = Pid::from_raw(pid);
    // Try SIGTERM first
    match kill(npid, Signal::SIGTERM) {
        Ok(_) => {}
        Err(nix::errno::Errno::ESRCH) => return Ok(()), // already gone
        Err(nix::errno::Errno::EPERM) => {
            // Permission denied; propagate a clear error
            return Err(anyhow!("permission denied sending SIGTERM"));
        }
        Err(e) => return Err(anyhow!("SIGTERM error: {e}")),
    }

    // Wait up to ~2 seconds for graceful exit
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match kill(npid, None) {
            Ok(_) => { /* still alive */ }
            Err(nix::errno::Errno::ESRCH) => return Ok(()),
            Err(e) => return Err(anyhow!("check alive error: {e}")),
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Force kill
    match kill(npid, Signal::SIGKILL) {
        Ok(_) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(nix::errno::Errno::EPERM) => Err(anyhow!("permission denied sending SIGKILL")),
        Err(e) => Err(anyhow!("SIGKILL error: {e}")),
    }
}

fn update_tray_ui(tray: &mut TrayIcon, snap: &ProcessSnapshot) {
    let count = snap.count();
    let title = count.to_string();
    let _ = tray.set_title(Some(&title));

    if count == 0 {
        let _ = tray.set_tooltip(Some("No dev servers 3000-10000"));
    } else {
        // Compact tooltip: list one port per PID
        let mut ports_list: Vec<u16> = snap
            .processes
            .values()
            .filter_map(|info| info.ports.iter().next().copied())
            .collect();
        ports_list.sort_unstable();
        let ports_str = ports_list
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = tray.set_tooltip(Some(&format!("{} on: {}", count, ports_str)));
    }
}

fn rebuild_dynamic_menu(tray: &mut TrayIcon, snap: &ProcessSnapshot, menu_state: &Arc<Mutex<MenuState>>) {
    // Recreate the menu fresh: process entries first, separator, then Kill All and Quit at bottom
    let menu = Menu::new();

    // Sort by smallest port for each pid to display a stable order
    let mut entries: Vec<(u16, &ProcessInfo)> = Vec::new();
    for info in snap.processes.values() {
        let first_port = info.ports.iter().next().copied().unwrap_or(0);
        entries.push((first_port, info));
    }
    entries.sort_by_key(|(p, _)| *p);

    // Add port items first
    for (port, info) in entries {
        let label = format!("Kill Port {}", port);
        let item = MenuItem::new(&label, true, None);
        let _ = menu.append(&item);
        if let Ok(mut state) = menu_state.lock() {
            state.pid_by_id.insert(item.id().clone(), info.pid);
        }
    }

    // Add separator
    let _ = menu.append(&PredefinedMenuItem::separator());

    // Add Kill All and Quit at the bottom
    let kill_all = MenuItem::new("Kill All", true, None);
    let quit = MenuItem::new("Quit", true, None);
    let _ = menu.append(&kill_all);
    let _ = menu.append(&quit);

    // Reset and store new IDs
    if let Ok(mut state) = menu_state.lock() {
        state.kill_all = kill_all.id().clone();
        state.quit = quit.id().clone();
    }

    let _ = tray.set_menu(Some(Box::new(menu)));
}
