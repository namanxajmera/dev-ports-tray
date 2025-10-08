# dev-ports-tray

A lightweight macOS status bar app that monitors development server ports (3000–10000) and lets you quickly terminate processes without switching to the terminal.

## Features

- **Live Port Monitoring** – Scans ports 3000–10000 every 2 seconds
- **Status Bar Integration** – Shows `0` when clear or `N⚠️` when N processes detected
- **Quick Actions** – Kill individual processes or all at once from the menu bar
- **Safe Termination** – Sends SIGTERM first, waits 2s, then SIGKILL if needed
- **Lightweight** – Native Rust, minimal memory footprint

## Installation

### Requirements
- macOS 10.15+ (Catalina or later)
- Rust toolchain ([install via rustup](https://rustup.rs/))
- `lsof` and `ps` (included in macOS)

### Build and Run
```sh
git clone https://github.com/namanxajmera/dev-ports-tray.git
cd dev-ports-tray
cargo run --release
```

The app will appear in your menu bar with a red dot icon.

## Usage

Once running, the app displays:
- **Title**: `0` (no processes) or `3⚠️` (3 processes detected)
- **Tooltip**: Hover to see which ports are in use
- **Menu**: Click the icon to see:
  - `Kill All Processes` – Terminate all detected processes
  - `Quit` – Exit the app
  - `Kill: Port 3001` – Individual process termination

### Notes
- If the same PID owns multiple ports, only the first port appears in the label
- Permission errors show in the tooltip – some processes may need elevated privileges
- Processes are terminated gracefully when possible

## Development

Built with Rust using:
- [`tray-icon`](https://crates.io/crates/tray-icon) – macOS menu bar integration
- [`winit`](https://crates.io/crates/winit) – Event loop
- `lsof` and `ps` – Process detection

To modify the port range, edit `PORT_START` and `PORT_END` in `src/main.rs:17-18`.

## Contributing

PRs welcome! Keep it simple:
- Match existing code style
- Test on macOS before submitting
- One feature per PR

## License

MIT License – Free to use, modify, and distribute.
