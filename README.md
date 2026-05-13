# MAC Changer v2

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux-111827)
![GUI](https://img.shields.io/badge/gui-PyQt6-14b8a6)
![Version](https://img.shields.io/badge/version-v2-2563eb)
![Status](https://img.shields.io/badge/status-active-2563eb)

MAC Changer is a dark glass PyQt6 desktop app for changing, restoring, tracking, and exporting MAC address changes on Kali Linux. It supports manual MAC entry, random rotation, vendor-based smart MAC generation, named profiles, live interface status, safer sudo validation, and session settings.

## Requirements

* Python `>=3.10`
* Kali Linux or a Linux system with `ip` from `iproute2`
* `sudo` for adapter changes
* PyQt6 from `requirements.txt`
* A network adapter that supports MAC address changes

## Quick Start

Kali Linux:

```bash
python3 RunMacChangerForKali.py
```

Run in the terminal foreground:

```bash
python3 RunMacChangerForKali.py --foreground
```

Custom script or dependency file:

```bash
python3 RunMacChangerForKali.py -f MAC_Changer.py -l requirements.txt
```

The launcher creates `myenv/`, installs packages from `requirements.txt`, validates required files, and starts the app. The app asks for sudo validation inside the Access tab before running adapter-changing actions.

## Main Areas

### Access

* Validates the sudo password with `sudo -S -v`
* Keeps the password only in memory for the current session
* Blocks MAC-changing actions until sudo is validated
* Shows current validation state

### Manual

* Select a network interface
* View live current MAC status
* Enter and apply a custom unicast MAC address
* Reset the selected interface to its saved default MAC
* Save, load, and delete named MAC profiles per interface
* Display and export manual logs and change records

### Auto

* Generate a one-click random unicast MAC
* Run scheduled MAC rotation with total changes and duration
* Reset the selected interface to its saved default MAC
* Display and export auto logs and change records
* Uses a busy state while actions are running

### Smart

* Generate a MAC from a selected vendor OUI prefix
* Search and filter vendors live
* Create a random vendor MAC in one click
* Add, edit, and delete vendor OUI data
* Display and export smart logs and change records

### Settings

* Theme mode: Dark Glass, Dark Compact, or High Contrast
* Auto-restore on close toggle
* Live interface refresh interval from `2` to `60` seconds
* Settings save to `data/settings.json`
* Timer changes apply without restarting the app

## Safety Behavior

* The app saves original/default MAC addresses in `data/default_mac_address.json`
* Restore All Defaults is available in Manual, Auto, and Smart tabs
* Auto-restore on close is enabled by default
* If `ip` is missing, the app shows: `The ip command was not found. Install iproute2.`
* If `sudo` is missing, the app shows: `sudo was not found. Install sudo or run in a supported Linux environment.`
* Adapter failures show the interface, failed step, target MAC when available, and the original command details

## Runtime Paths

* Vendor OUI data: `data/company_ouis.json`
* Saved default MACs: `data/default_mac_address.json`
* Manual changes: `data/changes_tracking.json`
* Auto changes: `data/auto_changes.json`
* Smart changes: `data/changes_smart.json`
* Named MAC profiles: `data/mac_profiles.json`
* App settings: `data/settings.json`
* Logs: `logs/mac_changer.log`
* Launcher setup log: `auto_setup.log`
* Virtual environment: `myenv/`

## Project Structure

```text
MAC-Changer/
|-- MAC_Changer.py
|-- RunMacChangerForKali.py
|-- requirements.txt
|-- README.md
|-- data/
|   `-- company_ouis.json
`-- mac_changer/
    |-- __init__.py
    |-- app.py
    |-- mac_tools.py
    `-- storage.py
```

## Development Run

```bash
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
python3 MAC_Changer.py
```

## Notes

* This tool is intended for your own adapters and authorized lab/testing environments
* Some wireless drivers or managed network states may reject MAC changes
* Running the UI on Windows is useful for development, but real adapter changes require Linux `ip` and `sudo`

## Versioning

* Current release: `v2`
* Git tag: `v2`
* Runtime data and local virtual environments are not part of release commits

## Links

* Repository: https://github.com/emaldos/MAC-Changer
* Issues: https://github.com/emaldos/MAC-Changer/issues
* Reference style: https://github.com/emaldos/LOYA-Note
