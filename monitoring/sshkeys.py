"""SSH key materialization for monitoring subsystem.

This intentionally mirrors the proven logic in `app.py` (key decryption layers,
normalization, safe temp-file write, and caching).
"""

from __future__ import annotations

import atexit
import os
import re
import tempfile
from typing import Optional

from database import SSHKey
from utils.sshkey_crypto import decrypt_str, normalize_ssh_key_text


# Cache SSH key temp files (ssh_key_id -> path)
_ssh_key_file_cache = {}


def cleanup_key_cache():
    for p in list(_ssh_key_file_cache.values()):
        try:
            if p and os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass


atexit.register(cleanup_key_cache)


def _write_temp_ssh_key_file(plaintext: str) -> str:
    """Write SSH key plaintext to a temp file in a way that avoids newline/encoding issues."""
    normalized = normalize_ssh_key_text(plaintext or '')
    if normalized and not normalized.endswith("\n"):
        normalized = normalized + "\n"
    tf = tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False)
    tf.write(normalized.encode('utf-8'))
    tf.flush()
    tf.close()
    os.chmod(tf.name, 0o600)
    return tf.name


def _sshkey_plaintext_from_model(key: SSHKey) -> str:
    """Return decrypted plaintext for a stored SSHKey row.

    Historical note: some rows ended up being encrypted multiple times due to earlier
    bugs/migrations. We attempt to decrypt repeatedly until the result resembles an
    SSH private key.
    """
    if not key:
        return ''

    content = key.key_content or ''
    if not getattr(key, 'is_encrypted', False):
        return content

    # Decrypt up to N layers. Stop once it looks like a private key.
    max_layers = 6
    for _layer in range(1, max_layers + 1):
        try:
            content = decrypt_str(content)
        except Exception:
            break

        # If we got something that looks like a private key, stop.
        if 'BEGIN' in content and 'PRIVATE KEY' in content and 'END' in content:
            break

        # If it still looks like an encoded blob (single-line token), keep going.
        if '\n' not in content and len(content) > 200 and re.fullmatch(r'[A-Za-z0-9_\-]+=*', content.strip()):
            continue

        # Otherwise: stop; we don't want to accidentally mangle non-token plaintext.
        break

    return content or ''


def materialize_ssh_key_path(ssh_key_id: Optional[int]) -> Optional[str]:
    """Return temp file path containing decrypted key; cached per key id."""
    if not ssh_key_id:
        return None

    ssh_key_id = int(ssh_key_id)
    cached = _ssh_key_file_cache.get(ssh_key_id)
    if cached and os.path.exists(cached):
        return cached

    key = SSHKey.query.get(ssh_key_id)
    if not key:
        return None

    content = _sshkey_plaintext_from_model(key)
    if not content:
        return None

    tf_name = _write_temp_ssh_key_file(content)
    _ssh_key_file_cache[ssh_key_id] = tf_name
    return tf_name
