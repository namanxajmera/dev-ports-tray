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

// Common development server ports
const DEV_PORTS: &[u16] = &[
    3000, // React, Next.js, create-react-app
    3001, // alternate React
    4200, // Angular
    5000, // Flask, various tools
    5173, // Vite
    5174, // Vite alternate
    8000, // Django, Python HTTP server
    8080, // common HTTP alternative
    8081, // common alternative
    8888, // Jupyter Notebook
    9000, // various tools
    9090, // Prometheus
];
const SCAN_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessInfo {
    pid: i32,
    ports: BTreeSet<u16>,
}

#[derive(Debug, Default, PartialEq, Eq)]
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
    UpdateSnapshot(Arc<ProcessSnapshot>),
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
    let event_loop: EventLoop<AppEvent> = match EventLoopBuilder::with_user_event()
        .with_activation_policy(ActivationPolicy::Accessory)
        .build()
    {
        Ok(el) => el,
        Err(e) => {
            eprintln!("Failed to create event loop: {}. The system may not support the required windowing features.", e);
            std::process::exit(1);
        }
    };

    #[cfg(not(target_os = "macos"))]
    let event_loop: EventLoop<AppEvent> = match EventLoopBuilder::with_user_event().build() {
        Ok(el) => el,
        Err(e) => {
            eprintln!("Failed to create event loop: {}. The system may not support the required windowing features.", e);
            std::process::exit(1);
        }
    };

    let proxy = event_loop.create_proxy();

    // Build tray icon with a visible red dot and initial menu
    let icon = match make_red_dot_icon(18) {
        Ok(icon) => icon,
        Err(e) => {
            eprintln!("Failed to create tray icon: {}", e);
            std::process::exit(1);
        }
    };
    let tray_menu = Menu::new();

    let mut tray = match TrayIconBuilder::new()
        .with_icon(icon)
        .with_menu(Box::new(tray_menu))
        .with_tooltip("No dev servers detected")
        .with_title("0")
        .build()
    {
        Ok(tray) => tray,
        Err(e) => {
            eprintln!("Failed to create tray icon: {}. Please check system tray permissions.", e);
            std::process::exit(1);
        }
    };

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
    let mut current_snapshot = Arc::new(ProcessSnapshot::default());

    // Track last snapshot used for the menu to avoid unnecessary rebuilds while hovering
    let mut last_built_menu_snapshot: Option<Arc<ProcessSnapshot>> = None;

    // Initial manual scan for immediate UI
    if let Ok(snap) = perform_scan() {
        let snap = Arc::new(snap);
        current_snapshot = Arc::clone(&snap);
        update_tray_ui(&mut tray, &snap);
        rebuild_dynamic_menu(&mut tray, &snap, &menu_state);
        last_built_menu_snapshot = Some(snap);
    }
    let _ = event_loop.run(move |event, elwt| {
        elwt.set_control_flow(ControlFlow::Wait);
        match event {
            Event::UserEvent(AppEvent::UpdateSnapshot(snap)) => {
                current_snapshot = Arc::clone(&snap);
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

fn make_red_dot_icon(size: u32) -> Result<Icon> {
    // Validate size to prevent excessive memory allocation
    if size == 0 {
        return Err(anyhow!("Icon size must be greater than 0"));
    }
    if size > 1024 {
        return Err(anyhow!("Icon size {} is too large (max 1024)", size));
    }

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
    Icon::from_rgba(rgba, size, size)
        .map_err(|e| anyhow!("Failed to create icon from RGBA data: {}", e))
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
                        let _ = proxy.send_event(AppEvent::UpdateSnapshot(Arc::new(snap)));
                    }
                    Err(e) => {
                        eprintln!("Scan error: {e:?}");
                        // Still send an empty snapshot to keep UI responsive
                        let _ = proxy.send_event(AppEvent::UpdateSnapshot(
                            Arc::new(ProcessSnapshot::default()),
                        ));
                    }
                }
            }
        }
    });
}

fn run_command_with_timeout(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output> {
    use std::process::Stdio;

    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", cmd, e))?;

    let pid = child.id();
    let start = Instant::now();

    // Poll for completion with timeout
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process completed, collect output
                let output = child.wait_with_output()
                    .map_err(|e| anyhow!("Failed to read output: {}", e))?;
                return Ok(output);
            }
            Ok(None) => {
                // Still running, check timeout
                if start.elapsed() > timeout {
                    // Timeout exceeded, kill the process
                    let _ = child.kill();
                    let _ = child.wait(); // Clean up zombie
                    return Err(anyhow!(
                        "Command '{}' timed out after {:?}",
                        cmd,
                        timeout
                    ));
                }
                // Sleep briefly before next check
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(anyhow!("Error waiting for command: {}", e));
            }
        }
    }
}

fn perform_scan() -> Result<ProcessSnapshot> {
    let mut pid_to_info: HashMap<i32, ProcessInfo> = HashMap::new();

    // Use a single lsof command to get all listening TCP processes
    // -nP: no hostname/service name resolution (faster)
    // -iTCP: only TCP connections
    // -sTCP:LISTEN: only listening sockets
    // Timeout after 5 seconds to prevent hanging
    let output = run_command_with_timeout("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"], Duration::from_secs(5))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse lsof output line by line
    // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // Example: node    12345 user 20u IPv4 0x123456 0t0 TCP *:3000 (LISTEN)
    for line in stdout.lines().skip(1) {  // Skip header line
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Need at least: COMMAND PID ... NAME
        if parts.len() < 9 {
            continue;
        }

        // Extract PID (column 1, 0-indexed)
        let pid = match i32::from_str(parts[1]) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Extract port from NAME column (last column)
        // Format can be: "*:3000" or "127.0.0.1:3000" or "[::]:3000"
        let name = parts[parts.len() - 2];  // -2 because last is often "(LISTEN)"
        let port = if let Some(colon_pos) = name.rfind(':') {
            match u16::from_str(&name[colon_pos + 1..]) {
                Ok(p) => p,
                Err(_) => continue,
            }
        } else {
            continue;
        };

        // Only track ports we care about
        if !DEV_PORTS.contains(&port) {
            continue;
        }

        // Add to or update the process info
        pid_to_info
            .entry(pid)
            .or_insert_with(|| ProcessInfo {
                pid,
                ports: BTreeSet::new(),
            })
            .ports
            .insert(port);
    }

    Ok(ProcessSnapshot { processes: pid_to_info })
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
        let _ = tray.set_tooltip(Some("No dev servers detected"));
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
