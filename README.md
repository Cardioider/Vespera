# Vespera Unsealer

> [!NOTE]
> **Reclaim Your Digital Freedom.** This project is designed to help users migrate digital assets from the Samsung ecosystem or Google Authenticator. Whether you want to break free from vendor lock-in, export "un-backupable" TOTP codes, or simply take true ownership of your private data, this tool is for you.
> 
> 
> *Note: As the original [**Unsealer**](https://github.com/Oracipher/Unsealer) project is under maintenance, I have archived the Unsealer repository and migrated the improved core code to this new repository (Vespera).*

<div align = "center">

<img src="https://github.com/Cardioider/Vespera/blob/main/src/media/favicon.ico" width="100" height="100" alt="Vespera icon">

</div>

<div align = "center">

[![GitHub Release](https://img.shields.io/github/v/release/Cardioider/Vespera?include_prereleases)](https://github.com/Cardioider/Vespera/releases)
[![PyPI Version](https://img.shields.io/pypi/v/unsealer)](https://pypi.org/project/unsealer/)
[![Python Versions](https://img.shields.io/badge/python-3.9+-brightgreen.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

**Take back your digital credentials.** Unsealer is a multi-module, open-source command-line utility designed to liberate your data from Samsung Pass (`.spass`) and Google Authenticator. It empowers you to securely decrypt and export sensitive information—including logins, identity details, addresses, and notes—into open, human-readable formats like CSV, TXT, or Markdown.

Whether you're migrating to a new password manager, creating a secure offline backup, or simply want true ownership of your digital life, Unsealer gives you back control.

<br>

> [!DANGER]
> **Security First: Read Before Use**
>
> This tool is a product of reverse engineering and is intended for personal data recovery and educational purposes only. It is NOT an official product of Samsung or Google.
>
> - **USE AT YOUR OWN RISK.** The author assumes no liability for data loss or security incidents.
> - **HANDLE DECRYPTED DATA CAREFULLY.** Decrypted data is stored in **plain text**. Store it in a secure location and avoid unnecessary sharing.
> - **100% OFFLINE & PRIVATE.** Unsealer runs entirely on your local machine. Recovery operations read local inputs and do not make network requests. Installing dependencies requires internet access. You are encouraged to audit the source code to verify this.

## Core Features

- **Samsung Module**: Decrypt and export logins, identities, addresses, secure notes, and **TOTP secrets**.
- **Google Module**: Parse `otpauth-migration://` URIs or directly extract 2FA secrets from Google Authenticator export QR codes. (Note: If you have many accounts, Google may generate multiple QR codes; ensure you scan all of them).
- **Multiple Export Formats**: Supports **CSV** (for spreadsheets), plain **TXT** (for readability), or structured **Markdown** (for reports).
- **Secure Interaction**: Enforces interactive password prompts to prevent your master password from being saved in shell history.
- **Instant Preview**: Inspect Samsung table counts or Google account labels without writing files. Preview does not print passwords or OTP secrets.
- **Cross-Platform Support**: Supports Windows, macOS (Intel and Apple Silicon), and Linux. Run via Python 3.9+ or use an available release binary. QR scanning requires ZBar; URI and JSON imports do not.

---

## Data Preparation

### 1. Obtain Samsung `.spass` File

You can obtain a backup in two ways:

<div align = "center">

<img src="https://github.com/Cardioider/Vespera/blob/main/src/media/smart_switch.png" width="50" height="50" alt="Smart Switch">

</div>

*   **Method A: Smart Switch (Desktop)**
    The `.spass` file is created via the [**Samsung Smart Switch**](https://www.samsung.com/us/support/owners/app/smart-switch) desktop app.
    
    1. Connect your phone to your PC/Mac via USB.
    2. Open Smart Switch and select **"Backup"**.
    3. Ensure **"Settings"** is checked (Samsung Pass data is stored here).
    4. After completion, find the `.spass` file in `\SAMSUNG\PASS\backup\`.

*   **Method B: Direct Export (Mobile)**
    1. Open Samsung Pass -> Settings -> Import and Export -> Export to `.spass`.
    2. Set an export password (**Crucial: Remember this password for decryption**).
    3. The file will be saved to your phone's internal storage.

### 2. Obtain Google Authenticator Data
1. In Google Authenticator, select "Transfer accounts" -> "Export accounts".
2. Take a screenshot of the QR code(s) or use a scanner to get the `otpauth-migration://` URL string.

---

## Step 2: Installation

### Method A: Direct Download (Recommended for most users)
Go to the [**Releases**](https://github.com/Cardioider/Vespera/releases) page and download the binary for your OS. It runs standalone without needing Python.

### Method B: Via PyPI
```bash
pip install unsealer
```
*Note: If `pip` is not found, try `pip3 install unsealer`.*

### Method C: From Source
```bash
git clone https://github.com/Cardioider/Vespera.git
cd Vespera
pip install .
```

---

## Step 3: Usage

Unsealer uses a subcommand structure.

### 1. Decrypt Samsung Pass (`.spass`)

```bash
# Basic export (Default: Markdown)
unsealer samsung ./my_backup.spass

# Preview mode (Display table counts only; no files are written)
unsealer samsung ./my_backup.spass --preview

# Export to Markdown at a specific path
unsealer samsung ./my_backup.spass -f md -o ./report.md
```

### 2. Extract Google 2FA (Authenticator)

<div align = "center">

<img src="https://github.com/Cardioider/Vespera/blob/main/src/media/authenticator%20wall.webp" width="400" alt="Google Authenticator Wallpaper">

</div>

```bash
# Extract from a migration string
unsealer google "otpauth-migration://offline?data=..." -o 2fa_backup.json

# Batch scan a folder of QR screenshots and generate a report
unsealer google ./qr_screenshots/ -o 2fa_backup.md
```

#### CLI Reference

Samsung usage: `unsealer samsung INPUT.spass [-f FORMAT] [-o PATH] [--preview]`.

| Option | Behavior |
| :--- | :--- |
| `input_file` | Required local Samsung Pass backup file. |
| `-f / --format` | `md` (default), `csv`, `txt`, or `json`. |
| `-o / --output` | Output path; defaults to the input filename with the chosen format's extension. |
| `--preview` | Show table counts; do not write files, even if `-o` is supplied. |

The backup/export password is always requested interactively. Password arguments are not supported.

Google usage: `unsealer google [INPUT ...] [-o PATH] [--preview]`.

| Option | Behavior |
| :--- | :--- |
| `inputs` | One or more migration URIs, QR images, image directories, or JSON exports. With no input, an interactive terminal prompts for one. |
| `-o / --output` | Infer the format from `.md`, `.csv`, `.txt`, or `.json` (Markdown when no extension is given). Without this option, only account labels are shown. |
| `--preview` | Show account labels without writing files, even if `-o` is supplied. |

- CSV output contains one file per table. For example, `-o backup.csv` creates `backup_export/`; the command prints the actual destination.
- JSON is the preferred format for lossless re-import. Google accepts either an account list or a `google_authenticator` list inside an export object.
- HOTP type and counter, algorithm, and digit count are preserved. Only identical account records are deduplicated.
- Supply **all** Google export QR codes together. The tool does not verify whether an entire multi-code export batch is present. Failed inputs return a non-zero exit status and prevent a partial Google export.
- An output path cannot replace an input file. Individual output files are replaced atomically; POSIX systems create them with owner-only permissions. CSV tables are written separately, so a later write failure can leave earlier tables on disk.

---

## FAQ

**Q: I get a "Decryption failed" error. What happened?**
A: This is usually caused by:
1. **Incorrect Password**: Use the password associated with that backup. For a direct mobile export, this is the custom password you set during export.
2. **Corrupted File**: The `.spass` file may be corrupted during transfer. Try creating a fresh backup.
3. **Incompatible Version**: While Samsung/Google formats have been stable for years, a major update might require a tool update.

**Q: Is it safe to handle my sensitive data with this tool?**
A: Yes, by design:
- **100% Offline**: No data ever leaves your machine.
- **Open Source**: The code is transparent and auditable by security experts.

**Q: What data can be exported?**
A: It parses credentials, identities, addresses, and secure notes from Samsung Pass, and TOTP secrets from Google Authenticator.

**Q: Error "libzbar.so not found" on Linux/macOS?**
A: The Google module's QR scanning depends on `zbar`. Install it via:
- Ubuntu/Debian: `sudo apt install libzbar0`
- macOS: `brew install zbar`

---

## Development

```bash
python -m pip install -e ".[test]" build pyinstaller
python -m pytest -q
python -m build
python scripts/smoke_test.py
```

The smoke checks use synthetic accounts and exercise the installed command, JSON round trips, failure exit codes, and real QR decoding. Install ZBar before running QR smoke checks on Linux/macOS. CI runs the tests on Python 3.9 and builds and tests executables on Windows, Linux, Intel macOS, and Apple Silicon macOS. Releases are published only for version tags after these checks pass.

## Acknowledgments

- Core decryption algorithms are based on the pioneering reverse engineering by **0xdeb7ef** in the [**spass-manager**](https://github.com/0xdeb7ef/spass-manager) project.
- Google migration protocol implementation was inspired by **Kristian Rekstad**'s [**google-authenticator-exporter**](https://github.com/krissrex/google-authenticator-exporter).
- Thanks to all developers contributing to the open-source security community.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
