# dev-ports-tray

A lightweight macOS status bar app that monitors common development server ports and lets you quickly terminate processes without switching to the terminal.

## Features

- **Live Port Monitoring** – Scans common dev ports (3000, 3001, 4200, 5000, 5173, 5174, 8000, 8080, 8081, 8888, 9000, 9090) every 2 seconds
- **Status Bar Integration** – Shows `0` when clear or `N` when N processes detected
- **Quick Actions** – Kill individual processes or all at once from the menu bar
- **Safe Termination** – Sends SIGTERM first, waits 2s, then SIGKILL if needed
- **Lightweight** – Native Rust, minimal memory footprint, single optimized lsof command

## Installation

### Requirements
- macOS 10.15+ (Catalina or later)
- Rust toolchain ([install via rustup](https://rustup.rs/))
- `lsof` (included in macOS)

### Build and Run
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

To modify which ports are monitored, edit the `DEV_PORTS` constant in `src/main.rs` (around line 21):

```rust
const DEV_PORTS: &[u16] = &[
    3000, // React, Next.js
    5173, // Vite
    8080, // Common HTTP
    // Add your ports here...
];
```

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
