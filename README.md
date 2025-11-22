# dev-ports-tray

A lightweight macOS status bar app that monitors common development server ports and lets you quickly terminate processes without switching to the terminal.

## Features

- **Live Port Monitoring** – Scans common dev ports (configurable) every 2 seconds
- **Status Bar Integration** – Shows `0` when clear or `N` when N processes detected
- **Quick Actions** – Kill individual processes or all at once from the menu bar
- **Configurable** – Add or remove ports directly from the menu (persisted to disk)
- **Safe Termination** – Sends SIGTERM first, waits 2s, then SIGKILL if needed
- **Lightweight** – Native Rust, minimal memory footprint, single optimized lsof command

## Installation

### Requirements
- macOS 10.15+ (Catalina or later)
- Rust toolchain ([install via rustup](https://rustup.rs/))
- `lsof` (included in macOS)

### Quick Install (Recommended)

Run the installation script to build and install the app to your `/Applications` folder:

```bash
./install.sh
```

This will:
1. Build the release binary
2. Create a standalone macOS app bundle (`DevPortsTray.app`)
3. Install it to `/Applications`

### Manual Build

```sh
git clone https://github.com/namanxajmera/dev-ports-tray.git
cd dev-ports-tray
cargo run --release
```

The app will appear in your menu bar with a red dot icon.

## Usage

Once running, the app displays:
- **Title**: `0` (no processes) or `3` (3 processes detected)
- **Tooltip**: Hover to see which ports are in use
- **Menu**: Click the icon to see:
  - Individual port options (e.g., `Kill Port 3000`) – Terminate specific process
  - `Add Port...` – Monitor a new port
  - `Remove Port` – Stop monitoring a specific port
  - `Kill All` – Terminate all detected processes
  - `Quit` – Exit the app

### Notes
- If the same PID owns multiple ports, only the first port appears in the label
- Permission errors show in the tooltip – some processes may need elevated privileges
- Processes are terminated gracefully when possible

## Development

Built with Rust using:
- [`tray-icon`](https://crates.io/crates/tray-icon) – macOS menu bar integration
- [`winit`](https://crates.io/crates/winit) – Event loop
- `lsof` – Process detection (single command with 5-second timeout)

### Customization


### Performance Optimizations

The codebase includes several optimizations:
- Single `lsof` command instead of multiple spawns (10x+ faster)
- Arc-based snapshot sharing (no deep clones)
- 5-second command timeout prevents hanging
- Graceful error handling (no panics)

## Contributing

PRs welcome! Keep it simple:
- Match existing code style
- Test on macOS before submitting
- One feature per PR

## License

MIT License – Free to use, modify, and distribute.
