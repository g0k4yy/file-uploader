# -*- coding: utf-8 -*-
# FileUploader.py - Burp Suite Jython 2.7 Extension
# Right-click on any request in Repeater/Proxy -> Extensions -> File Uploader

from burp import (IBurpExtender, IContextMenuFactory,
                  IHttpRequestResponse, IRequestInfo)
from javax.swing import (JPanel, JButton, JLabel, JTextField, JComboBox,
                         JTextArea, JScrollPane, BorderFactory, JOptionPane,
                         SwingUtilities, BoxLayout, JFileChooser, JDialog,
                         JRadioButton, ButtonGroup, JCheckBox, JSeparator,
                         JMenuItem, JTabbedPane, JToggleButton)
from javax.swing.border import TitledBorder
from java.awt import (GridBagLayout, GridBagConstraints, Insets, BorderLayout,
                      FlowLayout, Color, Font, Dimension)
from java.awt.event import ActionListener
from java.util import ArrayList
import base64
import hashlib
import hmac as _hmac_mod
import datetime
import binascii  # used for correct hex IV decoding under Jython 2.7 (see _parse_iv)
import jarray   # Jython built-in — needed for correct SecureRandom.nextBytes behaviour

# ─────────────────────────────────────────────────────────────────────────────
# EICAR test-file payloads  (embedded as base64 literals — no disk dependency)
# ─────────────────────────────────────────────────────────────────────────────

_EICAR_PRESETS = {
    # label -> (filename_hint, base64_payload)
    u"EICAR Standard (.com)": (
        "eicar.com",
        "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
    ),
    u"EICAR Standard (.txt)": (
        "eicar.txt",
        "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
    ),
    u"EICAR in ZIP (.zip)": (
        "eicar.zip",
        "UEsDBAoAAAAAAOCYuCg8z1FoRAAAAEQAAAAJAAAAZWljYXIuY29tWDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCpQSwECFAAKAAAAAADgmLgoPM9RaEQAAABEAAAACQAAAAAAAAABACAA/4EAAAAAZWljYXIuY29tUEsFBgAAAAABAAEANwAAAGsAAAAAAA=="
    ),
    u"EICAR in ZIP-of-ZIP (.zip)": (
        "eicar2.zip",
        "UEsDBAoAAAAAADKs6yjRINsxuAAAALgAAAANAAAAZWljYXJfY29tLnppcFBLAwQKAAAAAADgmLgoPM9RaEQAAABEAAAACQAAAGVpY2FyLmNvbVg1TyFQJUBBUFs0XFBaWDU0KFBeKTdDQyk3fSRFSUNBUi1TVEFOREFSRC1BTlRJVklSVVMtVEVTVC1GSUxFISRIK0gqUEsBAhQACgAAAAAA4Ji4KDzPUWhEAAAARAAAAAkAAAAAAAAAAQAgAP+BAAAAAGVpY2FyLmNvbVBLBQYAAAAAAQABADcAAABrAAAAAABQSwECFAAKAAAAAAAyrOso0SDbMbgAAAC4AAAADQAAAAAAAAAAACAAtoEAAAAAZWljYXJfY29tLnppcFBLBQYAAAAAAQABADsAAADjAAAAAAA="
    ),
}

_PRESET_LABELS = [u"-- Select preset file --"] + list(_EICAR_PRESETS.keys())

# ─────────────────────────────────────────────────────────────────────────────
# MIME type detection
#   Priority: magic bytes first (reliable), extension fallback, unknown last.
# ─────────────────────────────────────────────────────────────────────────────

# (offset, bytes_to_match, mime_type)
_MAGIC = [
    (0, b'\xff\xd8\xff',          u"image/jpeg"),
    (0, b'\x89PNG\r\n\x1a\n',     u"image/png"),
    (0, b'GIF87a',                 u"image/gif"),
    (0, b'GIF89a',                 u"image/gif"),
    (0, b'RIFF',                   u"image/webp"),   # refined below
    (0, b'BM',                     u"image/bmp"),
    (0, b'\x00\x00\x01\x00',       u"image/x-icon"),
    (0, b'%PDF-',                  u"application/pdf"),
    (0, b'PK\x03\x04',            u"application/zip"),
    (0, b'\x1f\x8b',              u"application/gzip"),
    (0, b'Rar!\x1a\x07',          u"application/x-rar-compressed"),
    (0, b'\x7fELF',               u"application/octet-stream"),
    (0, b'MZ',                     u"application/x-msdownload"),
    (0, b'\xca\xfe\xba\xbe',      u"application/java-vm"),
    (0, b'<?xml',                  u"text/xml"),
    (0, b'<html',                  u"text/html"),
    (0, b'<!DOCTYPE',              u"text/html"),
    (0, b'{\n',                    u"application/json"),
    (0, b'{"',                     u"application/json"),
]

_EXT_MIME = {
    u".jpg":  u"image/jpeg",   u".jpeg": u"image/jpeg",
    u".png":  u"image/png",    u".gif":  u"image/gif",
    u".webp": u"image/webp",   u".bmp":  u"image/bmp",
    u".ico":  u"image/x-icon", u".svg":  u"image/svg+xml",
    u".pdf":  u"application/pdf",
    u".zip":  u"application/zip",
    u".gz":   u"application/gzip",
    u".tar":  u"application/x-tar",
    u".rar":  u"application/x-rar-compressed",
    u".7z":   u"application/x-7z-compressed",
    u".exe":  u"application/x-msdownload",
    u".dll":  u"application/x-msdownload",
    u".xml":  u"text/xml",
    u".html": u"text/html",   u".htm":  u"text/html",
    u".json": u"application/json",
    u".txt":  u"text/plain",
    u".csv":  u"text/csv",
    u".js":   u"application/javascript",
    u".php":  u"application/x-php",
    u".sh":   u"application/x-sh",
    u".com":  u"application/octet-stream",  # EICAR
}

def _detect_mime(file_bytes, filename=None):
    """
    Guess MIME type from magic bytes first, then file extension, then unknown.
    Returns a unicode string like u"image/jpeg".
    """
    if file_bytes and len(file_bytes) >= 4:
        head = bytes(bytearray(file_bytes[:16]))
        # WEBP special case: RIFF????WEBP
        if head[:4] == b'RIFF' and len(head) >= 12 and head[8:12] == b'WEBP':
            return u"image/webp"
        for offset, magic, mime in _MAGIC:
            end = offset + len(magic)
            if head[offset:end] == magic:
                return mime

    if filename:
        dot = filename.rfind('.')
        if dot != -1:
            ext = filename[dot:].lower()
            if ext in _EXT_MIME:
                return _EXT_MIME[ext]

    return u"application/octet-stream"


# ─────────────────────────────────────────────────────────────────────────────
# Encoding / signing modes
#
#  0  Plain / Raw binary       (passthrough)
#  1  Base64                   (text output)
#  2  HMAC-SHA256              (hex text;  key field)
#  3  HMAC-SHA1                (hex text;  key field)
#  4  HMAC-MD5                 (hex text;  key field)
#  5  AES-CBC-128              (binary;    key + iv fields)
#  6  AES-GCM-128              (binary;    key + iv fields; tag appended)
# ─────────────────────────────────────────────────────────────────────────────

ENCODE_LABELS = [
    u"Plain / Raw binary",
    u"Base64",
    u"HMAC-SHA256 (hex)",
    u"HMAC-SHA1   (hex)",
    u"HMAC-MD5    (hex)",
    u"AES-CBC-128 (IV prepended to output)",
    u"AES-GCM-128 (IV prepended, tag appended)",
]

# Modes that need a key
_HMAC_MODES = set([2, 3, 4])
_AES_MODES  = set([5, 6])
_KEY_MODES  = _HMAC_MODES | _AES_MODES   # union — all need a key
_IV_MODES   = _AES_MODES                  # only AES needs separate IV field

# hashlib callables for HMAC — Jython 2.7 requires callables, not strings
_HMAC_ALGO = {
    2: hashlib.sha256,
    3: hashlib.sha1,
    4: hashlib.md5,
}


def _pad_key(key_str, length=16):
    """UTF-8 encode and zero-pad/truncate key_str to exactly `length` bytes."""
    raw = (key_str or u'').encode('utf-8')
    return (raw + b'\x00' * length)[:length]


def _parse_iv(iv_str, length=16):
    """
    Parse IV from hex string (preferred) or UTF-8 text, padded/truncated to `length`.
    Returns bytearray of exactly `length` bytes.
    """
    if not iv_str:
        return bytearray(length)                       # all-zero fallback
    s = iv_str.strip()
    # Try hex first.
    # FIX: the previous version called `bytes.fromhex(s)` on the non-str branch.
    # That's Python-3 idiom — under Jython 2.7, `bytes` IS `str`, and `str` has
    # no `fromhex` (only `bytearray.fromhex` exists in Py2). Worse, Swing's
    # getText() always returns `unicode`, never `str`, so the old code *always*
    # hit that broken branch, silently raised AttributeError, and fell through
    # to the UTF-8 fallback below — meaning a typed/auto-generated hex IV was
    # never actually used as raw bytes, only as literal text. binascii.unhexlify
    # works correctly in both Jython 2.7 and CPython for this.
    try:
        decoded = bytearray(binascii.unhexlify(s.encode('ascii')))
        return (decoded + bytearray(length))[:length]
    except Exception:
        pass
    # Fallback: UTF-8 bytes
    raw = s.encode('utf-8')
    return bytearray((raw + b'\x00' * length)[:length])


def encode_content(raw_bytes, mode, key=None, iv=None):
    """
    Transform raw_bytes according to mode.

    Returns bytearray for binary modes (0, 5, 6),
            unicode str  for text  modes (1, 2, 3, 4).

    Callers check isinstance(result, (bytes, bytearray)) for the binary path.
    """
    if mode == 0:
        return bytearray(raw_bytes)

    elif mode == 1:
        return base64.b64encode(bytes(bytearray(raw_bytes))).decode('ascii')

    elif mode in _HMAC_MODES:
        # IMPORTANT: pass hashlib callable, NOT a string — Jython 2.7 requires it
        key_bytes = (key or u'').encode('utf-8')
        h = _hmac_mod.new(key_bytes, bytes(bytearray(raw_bytes)), _HMAC_ALGO[mode])
        return h.hexdigest()

    elif mode == 5:
        # AES-CBC-128 using javax.crypto (always present on JVM/Jython)
        from javax.crypto import Cipher
        from javax.crypto.spec import SecretKeySpec, IvParameterSpec
        from java.security import SecureRandom
        key_padded = _pad_key(key or u'', 16)
        sk         = SecretKeySpec(key_padded, "AES")
        if iv is not None and iv.strip():
            iv_bytes = _parse_iv(iv, 16)
        else:
            # BUG FIX: SecureRandom.nextBytes on a Jython bytearray writes into a
            # temporary Java copy — the original stays zeroed.  Use jarray to get
            # a real Java byte[] that nextBytes modifies in-place, then convert.
            _sr      = SecureRandom()
            _iv_java = jarray.zeros(16, 'b')
            _sr.nextBytes(_iv_java)
            iv_bytes = bytearray([b & 0xFF for b in _iv_java])
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, sk, IvParameterSpec(bytes(iv_bytes)))
        ciphertext = bytearray(cipher.doFinal(bytes(bytearray(raw_bytes))))
        return bytearray(iv_bytes) + ciphertext

    elif mode == 6:
        # AES-GCM-128 — 12-byte IV is standard for GCM; tag is 128-bit (16 bytes)
        from javax.crypto import Cipher
        from javax.crypto.spec import SecretKeySpec, GCMParameterSpec
        from java.security import SecureRandom
        key_padded = _pad_key(key or u'', 16)
        sk         = SecretKeySpec(key_padded, "AES")
        if iv is not None and iv.strip():
            iv_bytes = _parse_iv(iv, 12)   # GCM standard: 96-bit nonce
        else:
            # BUG FIX: same jarray trick as AES-CBC above
            _sr      = SecureRandom()
            _iv_java = jarray.zeros(12, 'b')
            _sr.nextBytes(_iv_java)
            iv_bytes = bytearray([b & 0xFF for b in _iv_java])
        # GCMParameterSpec(tag_len_bits, iv_bytes)
        gcm_spec = GCMParameterSpec(128, bytes(iv_bytes))
        cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, sk, gcm_spec)
        # doFinal returns ciphertext || tag (128-bit tag appended automatically)
        ct_and_tag = bytearray(cipher.doFinal(bytes(bytearray(raw_bytes))))
        return bytearray(iv_bytes) + ct_and_tag

    return bytearray(raw_bytes)


def compute_hashes(raw_bytes):
    """Return ordered list of (algo_name, hexdigest) for display."""
    data = bytes(bytearray(raw_bytes))
    results = [
        ('MD5',       hashlib.md5(data).hexdigest()),
        ('SHA1',      hashlib.sha1(data).hexdigest()),
        ('SHA224',    hashlib.sha224(data).hexdigest()),
        ('SHA256',    hashlib.sha256(data).hexdigest()),
        ('SHA384',    hashlib.sha384(data).hexdigest()),
        ('SHA512',    hashlib.sha512(data).hexdigest()),
    ]
    # SHA3 variants — available in Python 3 / Jython 2.7.x (best-effort)
    for algo, attr in [('SHA3-224', 'sha3_224'), ('SHA3-256', 'sha3_256'),
                        ('SHA3-384', 'sha3_384'), ('SHA3-512', 'sha3_512')]:
        try:
            results.append((algo, getattr(hashlib, attr)(data).hexdigest()))
        except AttributeError:
            pass
    # BLAKE2 — Python 3.6+ / may not be present on all Jython builds
    for algo, attr in [('BLAKE2b', 'blake2b'), ('BLAKE2s', 'blake2s')]:
        try:
            results.append((algo, getattr(hashlib, attr)(data).hexdigest()))
        except (AttributeError, TypeError):
            pass
    return results


_ALL_HASH_ALGOS = [
    'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
    'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
    'BLAKE2b', 'BLAKE2s',
]


# ─────────────────────────────────────────────────────────────────────────────
# Utility: wrap a Python callable as a Java ActionListener  (Jython 2.7 safe)
# ─────────────────────────────────────────────────────────────────────────────

class _wrap_listener(ActionListener):
    def __init__(self, fn):
        self._fn = fn
    def actionPerformed(self, event):
        self._fn(event)


# ─────────────────────────────────────────────────────────────────────────────
# Replacement Dialog
# ─────────────────────────────────────────────────────────────────────────────

class ReplaceDialog(JDialog):
    """
    Modal dialog — two tabs:
      [Inject File]      browse / preset, encoding/signing, preview, apply
      [Hash Calculator]  MD5 / SHA1 / SHA256 / SHA512 of the loaded file
    """

    def __init__(self, parent_frame, selected_text):
        JDialog.__init__(self, parent_frame, u"File Uploader", True)
        self._result        = None   # (raw_bytes, mode_idx, key, iv) or None
        self._file_bytes    = None
        self._selected_text = selected_text
        self._build(parent_frame)

    # ── Top-level layout ───────────────────────────────────────────────────

    def _build(self, parent):
        outer = JPanel(BorderLayout(8, 8))
        outer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        tabs = JTabbedPane()
        tabs.addTab(u"Inject File",     self._build_inject_tab())
        tabs.addTab(u"Hash Calculator", self._build_hash_tab())
        outer.add(tabs, BorderLayout.CENTER)

        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        cancel_btn = JButton(u"Cancel")
        cancel_btn.addActionListener(_wrap_listener(lambda e: self.dispose()))
        apply_btn = JButton(u"Apply Replacement")
        apply_btn.setBackground(Color(60, 179, 113))
        apply_btn.setForeground(Color.WHITE)
        apply_btn.setFont(Font("SansSerif", Font.BOLD, 12))
        apply_btn.addActionListener(_wrap_listener(self._on_ok))
        btn_panel.add(cancel_btn)
        btn_panel.add(apply_btn)
        outer.add(btn_panel, BorderLayout.SOUTH)

        self.setContentPane(outer)
        self.pack()
        self.setMinimumSize(Dimension(640, 580))
        self.setLocationRelativeTo(parent)

    # ── Inject File tab ────────────────────────────────────────────────────

    def _build_inject_tab(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        center = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets  = Insets(4, 6, 4, 6)
        gbc.fill    = GridBagConstraints.HORIZONTAL

        row = [0]
        def R():
            r = row[0]; row[0] += 1; return r

        # ── Selected text preview ──────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 3, 1.0
        sel_lbl = JLabel(u"Selected text to replace:")
        sel_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        center.add(sel_lbl, gbc)

        gbc.gridy, gbc.weighty = R(), 0.25
        gbc.fill = GridBagConstraints.BOTH
        sel_preview = JTextArea(
            self._selected_text[:300] if self._selected_text else u"(nothing selected)", 3, 52)
        sel_preview.setEditable(False)
        sel_preview.setFont(Font("Monospaced", Font.PLAIN, 10))
        sel_preview.setBackground(Color(245, 245, 220))
        sel_preview.setLineWrap(True)
        sel_preview.setWrapStyleWord(True)
        center.add(JScrollPane(sel_preview), gbc)
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridy = R()
        center.add(JSeparator(), gbc)

        # ── File browse ────────────────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 1, 0.0
        center.add(JLabel(u"File to inject:"), gbc)

        gbc.gridx, gbc.weightx = 1, 1.0
        self._path_field = JTextField(u"No file selected", 32)
        self._path_field.setEditable(False)
        center.add(self._path_field, gbc)

        gbc.gridx, gbc.weightx, gbc.gridwidth = 2, 0.0, 1
        browse_btn = JButton(u"Browse\u2026")
        browse_btn.setBackground(Color(70, 130, 180))
        browse_btn.setForeground(Color.WHITE)
        browse_btn.addActionListener(_wrap_listener(self._on_browse))
        center.add(browse_btn, gbc)

        # ── Quick preset (below browse) ────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 1, 0.0
        center.add(JLabel(u"Quick preset:"), gbc)

        gbc.gridx, gbc.gridwidth, gbc.weightx = 1, 2, 1.0
        self._preset_combo = JComboBox(_PRESET_LABELS)
        self._preset_combo.addActionListener(_wrap_listener(self._on_preset_selected))
        center.add(self._preset_combo, gbc)

        gbc.gridy = R()
        center.add(JSeparator(), gbc)

        # ── Encoding / Signing ─────────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 1, 0.0
        center.add(JLabel(u"Encoding / Signing:"), gbc)

        gbc.gridx, gbc.gridwidth, gbc.weightx = 1, 2, 1.0
        self._enc_combo = JComboBox(ENCODE_LABELS)
        self._enc_combo.addActionListener(_wrap_listener(self._on_enc_changed))
        center.add(self._enc_combo, gbc)

        # ── Key row  (HMAC + AES) ──────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 1, 0.0
        self._key_lbl = JLabel(u"Key:")
        center.add(self._key_lbl, gbc)

        gbc.gridx, gbc.weightx = 1, 1.0
        self._key_field = JTextField(u"", 28)
        center.add(self._key_field, gbc)

        gbc.gridx, gbc.weightx, gbc.gridwidth = 2, 0.0, 1
        self._key_hint = JLabel(u"")
        self._key_hint.setFont(Font("SansSerif", Font.ITALIC, 10))
        self._key_hint.setForeground(Color(100, 100, 100))
        center.add(self._key_hint, gbc)

        # ── IV row  (AES only) ─────────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 1, 0.0
        self._iv_lbl = JLabel(u"IV (hex or text):")
        center.add(self._iv_lbl, gbc)

        gbc.gridx, gbc.weightx = 1, 1.0
        self._iv_field = JTextField(u"", 28)
        center.add(self._iv_field, gbc)

        gbc.gridx, gbc.weightx, gbc.gridwidth = 2, 0.0, 1
        self._iv_hint = JLabel(u"")
        self._iv_hint.setFont(Font("SansSerif", Font.ITALIC, 10))
        self._iv_hint.setForeground(Color(100, 100, 100))
        center.add(self._iv_hint, gbc)

        # ── Random IV button row ───────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 1, R(), 2, 1.0
        self._rand_iv_btn = JButton(u"Generate random IV")
        self._rand_iv_btn.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._rand_iv_btn.addActionListener(_wrap_listener(self._on_gen_iv))
        center.add(self._rand_iv_btn, gbc)

        gbc.gridy = R()
        center.add(JSeparator(), gbc)

        # ── Detected Content-Type (read-only + copy to clipboard) ─────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 1, 0.0
        ct_lbl = JLabel(u"Detected Content-Type:")
        ct_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        center.add(ct_lbl, gbc)

        gbc.gridx, gbc.weightx = 1, 1.0
        self._ct_field = JTextField(u"\u2014", 32)
        self._ct_field.setEditable(False)
        self._ct_field.setBackground(Color(240, 240, 240))
        self._ct_field.setToolTipText(
            u"MIME type detected from the loaded file's magic bytes / extension")
        center.add(self._ct_field, gbc)

        gbc.gridx, gbc.weightx, gbc.gridwidth = 2, 0.0, 1
        self._ct_copy_btn = JButton(u"Copy")
        self._ct_copy_btn.setToolTipText(u"Copy to clipboard")
        self._ct_copy_btn.addActionListener(_wrap_listener(self._on_ct_copy))
        center.add(self._ct_copy_btn, gbc)

        gbc.gridy = R()
        center.add(JSeparator(), gbc)

        # ── Preview area ───────────────────────────────────────────────────
        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weightx = 0, R(), 3, 1.0
        prev_lbl = JLabel(u"Preview (first 512 bytes shown as text or base64):")
        prev_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        center.add(prev_lbl, gbc)

        gbc.gridy, gbc.weighty = R(), 0.4
        gbc.fill = GridBagConstraints.BOTH
        self._preview_area = JTextArea(u"", 4, 52)
        self._preview_area.setEditable(False)
        self._preview_area.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._preview_area.setBackground(Color(230, 255, 230))
        self._preview_area.setLineWrap(True)
        self._preview_area.setWrapStyleWord(False)
        center.add(JScrollPane(self._preview_area), gbc)
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridy = R()
        preview_btn = JButton(u"Generate Preview")
        preview_btn.addActionListener(_wrap_listener(self._on_preview))
        center.add(preview_btn, gbc)

        panel.add(center, BorderLayout.CENTER)

        # initialise visibility
        self._update_enc_ui(0)
        return panel

    # ── Hash Calculator tab ────────────────────────────────────────────────

    def _build_hash_tab(self):
        panel = JPanel(BorderLayout(8, 8))
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))

        # ── Top: algorithm selector + calculate button ─────────────────────
        top_outer = JPanel(BorderLayout(6, 4))

        algo_lbl = JLabel(u"Select algorithms to compute:")
        algo_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        top_outer.add(algo_lbl, BorderLayout.NORTH)

        # Toggle buttons for each algorithm
        algo_toggle_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 4))
        algo_toggle_panel.setBorder(BorderFactory.createLineBorder(Color(180, 180, 180)))
        self._algo_toggles = {}
        # Default selected: MD5, SHA1, SHA256, SHA512
        _DEFAULT_ON = set(['MD5', 'SHA1', 'SHA256', 'SHA512'])
        for algo in _ALL_HASH_ALGOS:
            btn = JToggleButton(algo)
            btn.setSelected(algo in _DEFAULT_ON)
            btn.setFont(Font("Monospaced", Font.PLAIN, 10))
            btn.setMargin(Insets(2, 5, 2, 5))
            if algo.startswith('MD'):
                btn.setBackground(Color(255, 240, 200))
            elif algo.startswith('SHA3') or algo.startswith('BLAKE'):
                btn.setBackground(Color(220, 240, 255))
            elif algo.startswith('SHA5') or algo.startswith('SHA3-5'):
                btn.setBackground(Color(220, 255, 220))
            else:
                btn.setBackground(Color(240, 240, 240))
            self._algo_toggles[algo] = btn
            algo_toggle_panel.add(btn)

        # Select All / None shortcuts
        sel_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        all_btn  = JButton(u"All")
        none_btn = JButton(u"None")
        all_btn.setFont(Font("SansSerif", Font.PLAIN, 10))
        none_btn.setFont(Font("SansSerif", Font.PLAIN, 10))
        all_btn.setMargin(Insets(1, 6, 1, 6))
        none_btn.setMargin(Insets(1, 6, 1, 6))
        def _sel_all(e):
            for b in self._algo_toggles.values(): b.setSelected(True)
        def _sel_none(e):
            for b in self._algo_toggles.values(): b.setSelected(False)
        all_btn.addActionListener(_wrap_listener(_sel_all))
        none_btn.addActionListener(_wrap_listener(_sel_none))
        sel_panel.add(JLabel(u"Quick select:"))
        sel_panel.add(all_btn)
        sel_panel.add(none_btn)

        algo_wrap = JPanel(BorderLayout(0, 2))
        algo_wrap.add(algo_toggle_panel, BorderLayout.CENTER)
        algo_wrap.add(sel_panel, BorderLayout.SOUTH)
        top_outer.add(algo_wrap, BorderLayout.CENTER)

        # Info + calculate button
        ctrl_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        ctrl_panel.add(JLabel(u"File loaded from the 'Inject File' tab."))
        calc_btn = JButton(u"\u25b6  Calculate Hashes")
        calc_btn.setBackground(Color(60, 150, 220))
        calc_btn.setForeground(Color.WHITE)
        calc_btn.setFont(Font("SansSerif", Font.BOLD, 11))
        calc_btn.addActionListener(_wrap_listener(self._on_calc_hashes))
        ctrl_panel.add(calc_btn)

        copy_all_btn = JButton(u"\u2398  Copy All")
        copy_all_btn.setFont(Font("SansSerif", Font.PLAIN, 11))
        copy_all_btn.setToolTipText(u"Copy all computed hashes to clipboard")
        copy_all_btn.addActionListener(_wrap_listener(self._on_copy_all_hashes))
        ctrl_panel.add(copy_all_btn)
        top_outer.add(ctrl_panel, BorderLayout.SOUTH)

        panel.add(top_outer, BorderLayout.NORTH)

        # ── Center: results cards ──────────────────────────────────────────
        # Each result is a row: [algo label] [hash field] [Copy btn]
        self._hash_result_panel = JPanel()
        self._hash_result_panel.setLayout(BoxLayout(self._hash_result_panel, BoxLayout.Y_AXIS))
        self._hash_result_panel.setBackground(Color(245, 247, 250))
        self._hash_fields = {}        # algo -> JTextField
        self._hash_copy_btns = {}     # algo -> JButton
        self._computed_hashes = {}    # algo -> hexdigest (populated on calculate)

        # Build placeholder rows (hidden until calculated)
        _ALGO_COLORS = {
            'MD5':      Color(255, 240, 200),
            'SHA1':     Color(255, 228, 196),
            'SHA224':   Color(240, 248, 255),
            'SHA256':   Color(220, 245, 220),
            'SHA384':   Color(210, 240, 210),
            'SHA512':   Color(195, 235, 195),
            'SHA3-224': Color(230, 220, 255),
            'SHA3-256': Color(225, 215, 255),
            'SHA3-384': Color(215, 205, 255),
            'SHA3-512': Color(205, 195, 255),
            'BLAKE2b':  Color(255, 220, 230),
            'BLAKE2s':  Color(255, 210, 220),
        }
        for algo in _ALL_HASH_ALGOS:
            row_panel = JPanel(BorderLayout(6, 2))
            row_panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color(210, 210, 210)),
                BorderFactory.createEmptyBorder(5, 8, 5, 8)
            ))
            row_panel.setBackground(_ALGO_COLORS.get(algo, Color(245, 245, 245)))
            row_panel.setMaximumSize(Dimension(10000, 38))

            lbl = JLabel(algo)
            lbl.setFont(Font("Monospaced", Font.BOLD, 11))
            lbl.setForeground(Color(50, 50, 80))
            lbl.setPreferredSize(Dimension(78, 22))
            row_panel.add(lbl, BorderLayout.WEST)

            tf = JTextField(u"\u2014  (not computed)", 60)
            tf.setEditable(False)
            tf.setFont(Font("Monospaced", Font.PLAIN, 11))
            tf.setBackground(Color(252, 252, 252))
            tf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(2, 4, 2, 4)
            ))
            self._hash_fields[algo] = tf
            row_panel.add(tf, BorderLayout.CENTER)

            copy_btn = JButton(u"Copy")
            copy_btn.setFont(Font("SansSerif", Font.PLAIN, 10))
            copy_btn.setMargin(Insets(2, 6, 2, 6))
            copy_btn.setEnabled(False)
            # Closure: capture algo name
            def _make_copy_fn(a):
                def _copy(e):
                    val = self._hash_fields[a].getText().strip()
                    if val and not val.startswith(u"\u2014"):
                        from java.awt import Toolkit
                        from java.awt.datatransfer import StringSelection
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                            StringSelection(val), None)
                        self._hash_copy_btns[a].setText(u"\u2713 Copied")
                        import threading
                        def _reset():
                            import time; time.sleep(1.5)
                            SwingUtilities.invokeLater(
                                lambda: self._hash_copy_btns[a].setText(u"Copy"))
                        threading.Thread(target=_reset).start()
                return _copy
            copy_btn.addActionListener(_wrap_listener(_make_copy_fn(algo)))
            self._hash_copy_btns[algo] = copy_btn
            row_panel.add(copy_btn, BorderLayout.EAST)

            self._hash_result_panel.add(row_panel)

        # File size label at top of results
        self._hash_size_lbl = JLabel(u"  Load a file on the 'Inject File' tab, then click Calculate.")
        self._hash_size_lbl.setFont(Font("SansSerif", Font.ITALIC, 11))
        self._hash_size_lbl.setForeground(Color(100, 100, 100))
        self._hash_size_lbl.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8))

        results_wrap = JPanel(BorderLayout(0, 0))
        results_wrap.add(self._hash_size_lbl, BorderLayout.NORTH)
        results_wrap.add(self._hash_result_panel, BorderLayout.CENTER)

        panel.add(JScrollPane(results_wrap), BorderLayout.CENTER)
        return panel

    # ── Listeners ──────────────────────────────────────────────────────────

    def _on_browse(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle(u"Select file to inject")
        if chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            f    = chooser.getSelectedFile()
            path = f.getAbsolutePath()
            self._path_field.setText(path)
            with open(path, 'rb') as fh:
                self._file_bytes = bytearray(fh.read())
            self._preview_area.setText(u"")
            self._preset_combo.setSelectedIndex(0)
            self._ct_field.setText(_detect_mime(self._file_bytes, f.getName()))

    def _on_preset_selected(self, event):
        label = self._preset_combo.getSelectedItem()
        if label not in _EICAR_PRESETS:
            return
        filename, b64 = _EICAR_PRESETS[label]
        self._file_bytes = bytearray(base64.b64decode(b64))
        self._path_field.setText(u"[Preset] " + filename)
        self._preview_area.setText(u"")
        self._ct_field.setText(_detect_mime(self._file_bytes, filename))

    def _on_enc_changed(self, event):
        mode = self._enc_combo.getSelectedIndex()
        self._update_enc_ui(mode)

    def _update_enc_ui(self, mode):
        """Show / hide key + IV rows based on selected mode."""
        need_key = mode in _KEY_MODES
        need_iv  = mode in _IV_MODES

        self._key_lbl.setVisible(need_key)
        self._key_field.setVisible(need_key)
        self._key_hint.setVisible(need_key)
        self._iv_lbl.setVisible(need_iv)
        self._iv_field.setVisible(need_iv)
        self._iv_hint.setVisible(need_iv)
        self._rand_iv_btn.setVisible(need_iv)

        if mode in _HMAC_MODES:
            self._key_hint.setText(u"Required — any UTF-8 string")
        elif mode in _AES_MODES:
            self._key_hint.setText(u"Up to 16 chars (zero-padded to 16 bytes)")
        else:
            self._key_hint.setText(u"")

        if mode == 5:
            self._iv_hint.setText(u"16-byte IV — hex (32 hex chars) or text. Leave blank for random.")
        elif mode == 6:
            self._iv_hint.setText(u"12-byte nonce — hex (24 hex chars) or text. Leave blank for random.")

    def _on_ct_copy(self, event):
        """Copy the detected Content-Type value to the system clipboard."""
        val = self._ct_field.getText().strip()
        if val and val != u"\u2014":
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(val), None)
            self._ct_copy_btn.setText(u"Copied!")
            import threading
            def _reset():
                import time; time.sleep(1.5)
                SwingUtilities.invokeLater(lambda: self._ct_copy_btn.setText(u"Copy"))
            threading.Thread(target=_reset).start()

    def _on_gen_iv(self, event):
        """Fill IV field with a freshly generated random value (hex)."""
        from java.security import SecureRandom
        mode   = self._enc_combo.getSelectedIndex()
        length = 12 if mode == 6 else 16
        # BUG FIX: use jarray so nextBytes writes into the real Java byte[],
        # not a Jython-side copy that gets discarded.
        _sr      = SecureRandom()
        _iv_java = jarray.zeros(length, 'b')
        _sr.nextBytes(_iv_java)
        iv_bytes = bytearray([b & 0xFF for b in _iv_java])
        hex_iv   = ''.join('{:02x}'.format(b) for b in iv_bytes)
        self._iv_field.setText(hex_iv)

    def _on_preview(self, event):
        if self._file_bytes is None:
            JOptionPane.showMessageDialog(
                self, u"Please select a file or preset first.",
                u"No file", JOptionPane.WARNING_MESSAGE)
            return
        mode = self._enc_combo.getSelectedIndex()
        key  = self._key_field.getText() if mode in _KEY_MODES else None
        iv   = self._iv_field.getText()  if mode in _IV_MODES  else None
        try:
            result = encode_content(self._file_bytes, mode, key=key, iv=iv)
            if isinstance(result, (bytes, bytearray)):
                snippet = bytes(bytearray(result[:512]))
                b64snip = base64.b64encode(snippet).decode('ascii')
                display = u"[Binary — {} total bytes]\nBase64 of first 512 bytes:\n{}{}".format(
                    len(result), b64snip,
                    u"\u2026" if len(result) > 512 else u"")
            else:
                display = result[:512] + (u"\u2026" if len(result) > 512 else u"")
            self._preview_area.setText(display)
        except Exception as ex:
            self._preview_area.setText(u"Error: " + str(ex))

    def _on_calc_hashes(self, event):
        if self._file_bytes is None:
            self._hash_size_lbl.setText(
                u"  No file loaded. Browse or pick a preset on the 'Inject File' tab.")
            return

        # Reset all fields
        for algo in _ALL_HASH_ALGOS:
            self._hash_fields[algo].setText(u"\u2014  (not selected)")
            self._hash_copy_btns[algo].setEnabled(False)

        selected = [a for a in _ALL_HASH_ALGOS
                    if self._algo_toggles.get(a) and self._algo_toggles[a].isSelected()]
        if not selected:
            self._hash_size_lbl.setText(u"  No algorithms selected — use the toggles above.")
            return

        self._hash_size_lbl.setText(
            u"  File size: {:,} bytes   |   Computing {} algorithm(s)\u2026".format(
                len(self._file_bytes), len(selected)))

        data = bytes(bytearray(self._file_bytes))
        _algo_fn = {
            'MD5':      lambda d: hashlib.md5(d).hexdigest(),
            'SHA1':     lambda d: hashlib.sha1(d).hexdigest(),
            'SHA224':   lambda d: hashlib.sha224(d).hexdigest(),
            'SHA256':   lambda d: hashlib.sha256(d).hexdigest(),
            'SHA384':   lambda d: hashlib.sha384(d).hexdigest(),
            'SHA512':   lambda d: hashlib.sha512(d).hexdigest(),
            'SHA3-224': lambda d: getattr(hashlib, 'sha3_224')(d).hexdigest(),
            'SHA3-256': lambda d: getattr(hashlib, 'sha3_256')(d).hexdigest(),
            'SHA3-384': lambda d: getattr(hashlib, 'sha3_384')(d).hexdigest(),
            'SHA3-512': lambda d: getattr(hashlib, 'sha3_512')(d).hexdigest(),
            'BLAKE2b':  lambda d: getattr(hashlib, 'blake2b')(d).hexdigest(),
            'BLAKE2s':  lambda d: getattr(hashlib, 'blake2s')(d).hexdigest(),
        }

        computed = 0
        for algo in selected:
            fn = _algo_fn.get(algo)
            if fn is None:
                self._hash_fields[algo].setText(u"\u2014  (not available)")
                continue
            try:
                digest = fn(data)
                self._hash_fields[algo].setText(digest)
                self._hash_copy_btns[algo].setEnabled(True)
                self._computed_hashes[algo] = digest
                computed += 1
            except Exception as ex:
                self._hash_fields[algo].setText(u"\u2014  error: {}".format(str(ex)))

        self._hash_size_lbl.setText(
            u"  File size: {:,} bytes   |   {} / {} algorithms computed successfully".format(
                len(self._file_bytes), computed, len(selected)))

    def _on_copy_all_hashes(self, event):
        """Copy all computed hashes to clipboard as multiline text."""
        lines = []
        for algo in _ALL_HASH_ALGOS:
            val = self._hash_fields[algo].getText().strip()
            if val and not val.startswith(u"\u2014"):
                lines.append(u"{}: {}".format(algo, val))
        if not lines:
            JOptionPane.showMessageDialog(
                self, u"No hashes computed yet. Click 'Calculate Hashes' first.",
                u"Nothing to copy", JOptionPane.INFORMATION_MESSAGE)
            return
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            StringSelection(u"\n".join(lines)), None)

    def _on_ok(self, event):
        if self._file_bytes is None:
            JOptionPane.showMessageDialog(
                self, u"Please select a file or preset first.",
                u"No file", JOptionPane.WARNING_MESSAGE)
            return
        mode = self._enc_combo.getSelectedIndex()
        key  = self._key_field.getText() if mode in _KEY_MODES else None
        iv   = self._iv_field.getText()  if mode in _IV_MODES  else None

        # BUG FIX 4: warn when a keyed mode has no key supplied
        if mode in _KEY_MODES and not (key and key.strip()):
            ans = JOptionPane.showConfirmDialog(
                self,
                u"The selected mode requires a key but the Key field is empty.\n"
                u"AES will use an all-zero key; HMAC will use an empty secret.\n\n"
                u"Continue anyway?",
                u"Empty key",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE)
            if ans != JOptionPane.YES_OPTION:
                return

        # HMAC semantic note — shown once per dialog open, non-blocking
        if mode in _HMAC_MODES:
            print(u"[NOTE] HMAC mode outputs the *signature* of the file, not the file "
                  u"itself.  The request body will contain the hex HMAC digest.")

        self._result = (self._file_bytes, mode, key, iv)
        self.dispose()

    def get_result(self):
        """Returns (raw_bytes, mode_idx, key, iv) or None if cancelled."""
        return self._result   # None if cancelled


# ─────────────────────────────────────────────────────────────────────────────
# Main extender
# ─────────────────────────────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(u"File Uploader")
        callbacks.registerContextMenuFactory(self)
        print(u"[*] File Uploader loaded.")
        print(u"[*] Right-click any request in Repeater or Intruder -> Extensions -> File Uploader")

    # ── Context menu ──────────────────────────────────────────────────────

    def createMenuItems(self, invocation):
        # Support Repeater, Intruder and Proxy tool contexts.
        #
        # Burp Suite 1.x exposed TOOL_* constants on the invocation object itself
        # (IContextMenuInvocation).  Burp Suite 2.x removed them from the instance
        # — they only exist on the *class* (or not at all in obfuscated builds).
        # We resolve the constants safely: try the class first, then fall back to
        # the well-known numeric literals that have been stable across all versions.
        #   TOOL_PROXY    = 4
        #   TOOL_INTRUDER = 32
        #   TOOL_REPEATER = 64
        try:
            from burp import IContextMenuInvocation
            TOOL_REPEATER = IContextMenuInvocation.TOOL_REPEATER
            TOOL_INTRUDER = IContextMenuInvocation.TOOL_INTRUDER
            TOOL_PROXY    = IContextMenuInvocation.TOOL_PROXY
        except Exception:
            TOOL_PROXY    = 4
            TOOL_INTRUDER = 32
            TOOL_REPEATER = 64

        tool = invocation.getToolFlag()
        SUPPORTED = set([TOOL_REPEATER, TOOL_INTRUDER, TOOL_PROXY])
        if tool not in SUPPORTED:
            return None
        items = ArrayList()
        item  = JMenuItem(u"File Uploader")
        item.addActionListener(_wrap_listener(
            lambda e: self._handle_invocation(invocation)
        ))
        items.add(item)
        return items

    # ── Core handler ──────────────────────────────────────────────────────

    def _handle_invocation(self, invocation):
        """
        Replaces the currently selected byte range in the editor with the
        encoded/encrypted file content.  A selection is required; if nothing
        is selected the operation is aborted with a warning.
        """
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return

        msg       = messages[0]
        req_bytes = msg.getRequest()

        # Require an explicit selection — no auto-detection fallback.
        bounds        = None
        selected_text = u""
        try:
            bounds = invocation.getSelectionBounds()
            if bounds is not None and len(bounds) == 2 and bounds[1] > bounds[0]:
                sel_bytes     = req_bytes[bounds[0]:bounds[1]]
                selected_text = bytes(bytearray(sel_bytes)).decode('utf-8', errors='replace')
            else:
                bounds = None
        except Exception:
            bounds = None

        if bounds is None:
            from javax.swing import JOptionPane
            frame = None
            try:
                frame = self._callbacks.getSuiteFrame()
            except AttributeError:
                pass
            JOptionPane.showMessageDialog(
                frame,
                u"Please select the text you want to replace in the editor first.",
                u"No selection",
                JOptionPane.WARNING_MESSAGE)
            return

        # Parent frame
        frame = None
        try:
            frame = self._callbacks.getSuiteFrame()
        except AttributeError:
            pass

        dlg = ReplaceDialog(frame, selected_text)
        dlg.setVisible(True)   # modal — blocks

        result = dlg.get_result()
        if result is None:
            return

        raw_bytes, mode_idx, key, iv = result
        encoded   = encode_content(raw_bytes, mode_idx, key=key, iv=iv)
        is_binary = isinstance(encoded, (bytes, bytearray))

        if is_binary:
            new_bytes = bytearray(encoded)
        else:
            new_bytes = bytearray(encoded.encode('utf-8'))

        new_req = self._splice_selection(req_bytes, bounds[0], bounds[1], new_bytes)
        msg.setRequest(new_req)
        self._log(u"Selection replaced ({}-{}) with {} content ({} bytes)".format(
            bounds[0], bounds[1], ENCODE_LABELS[mode_idx], len(encoded)))

    # ── Splice helper ─────────────────────────────────────────────────────

    def _splice_selection(self, req_bytes, start, end, new_bytes):
        result = bytearray()
        result.extend(bytearray(req_bytes[:start]))
        result.extend(bytearray(new_bytes))
        result.extend(bytearray(req_bytes[end:]))
        return bytes(result)

    # ── Log ───────────────────────────────────────────────────────────────

    def _log(self, msg):
        ts   = datetime.datetime.now().strftime("%H:%M:%S")
        line = u"[{}] {}\n".format(ts, msg)
        print(line.rstrip())
