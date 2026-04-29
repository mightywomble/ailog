from __future__ import annotations

import atexit
import os
import stat
import tempfile
from typing import Optional

from database import SSHKey, db
from utils.sshkey_crypto import decrypt_str, normalize_ssh_key_text


_key_cache = {}  # ssh_key_id -> path


def cleanup_key_cache():
    for _, path in list(_key_cache.items()):
        try:
            os.unlink(path)
        except Exception:
            pass
    _key_cache.clear()


atexit.register(cleanup_key_cache)


def _write_temp_pem(plaintext: str) -> str:
    tf = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
    tf.write(plaintext)
    tf.flush()
    tf.close()
    os.chmod(tf.name, stat.S_IRUSR | stat.S_IWUSR)
    return tf.name


def materialize_ssh_key_path(ssh_key_id: Optional[int]) -> Optional[str]:
    if not ssh_key_id:
        return None
    if ssh_key_id in _key_cache:
        return _key_cache[ssh_key_id]

    key = db.session.get(SSHKey, int(ssh_key_id))
    if not key or not key.key_content:
        return None

    content = key.key_content
    try:
        # Try decrypt if marked encrypted; tolerate plaintext.
        if getattr(key, 'is_encrypted', False):
            # Some keys have multiple layers; try a few.
            for _ in range(6):
                try:
                    content = decrypt_str(content)
                except Exception:
                    break
    except Exception:
        pass

    try:
        content = normalize_ssh_key_text(content)
    except Exception:
        pass

    if 'BEGIN' not in content or 'PRIVATE KEY' not in content:
        # Still write it; SSH will reject if invalid.
        pass

    path = _write_temp_pem(content)
    _key_cache[ssh_key_id] = path
    return path
