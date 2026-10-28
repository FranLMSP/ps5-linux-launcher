<p align="center">
 <img src="./assets/icon.svg" width="128" />
</p>
<h1 align="center">PS5 Linux Launcher</h1>
&nbsp;
<p align="center">One-click launcher to boot Linux on your PS5.<br>Supports firmwares <b>7.00&ndash;13.60</b> (tested primarily on <b>12.60</b>).</p>

## What this does

PS5 Linux Launcher is a fork/customization of [ps5-webkit-autoloader](https://github.com/itsPLK/ps5-webkit-autoloader). When launched from the PS5 homescreen:

1. It runs the WebKit exploit (Poops/Relapse) via the autoloader.
2. Instead of letting you choose arbitrary payloads, it automatically loads `ps5-linux-loader.elf` (from this fork) to boot Linux.
3. Everything is served offline from the console after a one-time install (no third-party DNS required).

> Note: The bundled `ps5-linux-loader.elf` in this repo is known to be compatible with **12.60** (the console it was tested on). Other firmwares may need a loader built for them.

## Setup Instructions

There are two ways to install the launcher. You can install the launcher itself as a payload (e.g. via Payload Manager) or host/setup via PC.

### Option 1: Install via Payload Manager (recommended)
This is convenient if you already run Payload Manager or want to install directly from a payload environment.

1. Download the latest release artifacts from this repo (or build them). You need:
   - `ps5-linux-launcher-installer_vX.Y.Z.elf` (installer payload)
   - or use the host script if doing PC-hosted setup
2. Send `ps5-linux-launcher-installer.elf` to your PS5 using Payload Manager / elfldr / your preferred payload sender.
3. The installer will open the browser to cache the launcher page, create the **PS5 Linux Launcher** app on the homescreen, and exit.
4. Reboot once, then launch **PS5 Linux Launcher** from the homescreen.

### Option 2: PC-hosted setup (if not jailbroken yet)
If you aren't jailbroken yet, host the exploit locally on your PC:

1. Download `ps5-linux-launcher-host.py` (or `.exe`) from the Releases page and run it on a PC on the same network.
2. On your PS5, set your network's DNS server to your PC's IP address.
3. Open the **User's Guide** from Settings to run the installer, which will add **PS5 Linux Launcher** to your homescreen.
4. Reboot once, then launch **PS5 Linux Launcher** from the homescreen.

## How to Use

1. Make sure you have your Linux USB drive prepared (see [ps5-linux](https://github.com/ps5-linux/ps5-linux) installation docs).
2. Launch **PS5 Linux Launcher** from the PS5 homescreen.
3. The launcher will select the appropriate exploit for your firmware (or prompt if both are supported), run it, and automatically send `ps5-linux-loader.elf` to boot Linux.
4. Follow the normal Linux boot sequence (rest mode/power button as described in ps5-linux docs).

## Building from source

Requirements:
- PS5 Payload SDK installed at `/opt/ps5-payload-sdk` (or set `SDK` in Makefile)
- Docker (for the full release build script)
- Python 3, Node.js (for tests/tools)

Build artifacts:
```bash
# Build installer ELF
make clean && make all

# Build PC host script
make host

# Or build full release bundle
./build_release.sh
```

The autoloader will embed `ps5-linux-loader.elf` from `./ps5-linux-loader.elf` or `build/deps/autoload.elf`. Place your desired loader there before building.

## Credits

- Based on [ps5-webkit-autoloader](https://github.com/itsPLK/ps5-webkit-autoloader) by PLK
- [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) by ps5-linux team (TheOfficialFloW, etc.)
- Exploits by [jordyidk/slopkit](https://github.com/jordyidk/slopkit) (Poops) and [soniciso1/Relapse](https://github.com/soniciso1/relapse)
- [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) and [elfldr](https://github.com/ps5-payload-dev/elfldr) by john-tornblom

## License

GPL-3.0
