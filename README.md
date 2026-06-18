# File Uploader — Burp Suite Extension

A Burp Suite Jython 2.7 extension for injecting, encoding, signing, and encrypting arbitrary file content into HTTP requests directly from Repeater, Intruder, or Proxy. 

Designed for penetration testers testing file upload endpoints, HMAC-signed APIs, and AES-encrypted payloads.

---

## Installation

**Requirements:** Burp Suite (any edition) and Jython Standalone 2.7.x.

1. In Burp, go to `Extender` → `Options` → `Python Environment` and set the path to your `jython-standalone-2.7.x.jar`.
2. Go to `Extender` → `Extensions` → `Add`, set Extension Type to `Python`, and select `FileUploader.py`.
3. Click `Next`. The output panel should show `[*] File Uploader loaded.`

---

## Usage

1. Open a request in Repeater, Intruder, or Proxy.
2. Select the text you want to replace in the editor.
3. Right-click → `Extensions` → `File Uploader`.
4. In the dialog, browse for a file or pick an EICAR preset, choose an encoding mode, fill in key/IV if required, and click `Apply Replacement`.

A selection is required. If nothing is selected when the menu item is clicked, the extension shows a warning and does nothing.

---

## EICAR Presets

The extension ships four built-in EICAR test file variants, embedded as Base64 literals with no disk dependency.

- EICAR Standard (.com) — standard antivirus test string
- EICAR Standard (.txt) — same content, different extension
- EICAR in ZIP (.zip) — single-level archive
- EICAR in ZIP-of-ZIP (.zip) — double-nested archive

These are useful for testing antivirus bypass scenarios on upload endpoints.

---

## Hash Calculator

The Hash Calculator tab computes hashes of the loaded file. Supported algorithms: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2b, BLAKE2s.

Toggle individual algorithms using the buttons at the top. SHA-3 and BLAKE2 variants are silently skipped if unavailable in the current Jython build. Individual hashes or all computed hashes can be copied to the clipboard.

---

## Disclaimer

This tool is intended for authorized security testing only. Use it only on systems you have explicit permission to test. The EICAR test files embedded in the extension are harmless detection-test strings, not real malware.
+
