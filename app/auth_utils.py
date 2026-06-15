import hashlib
import os
import hmac

_ALGORITHM = "sha256"
_ITERATIONS = 100_000
_SALT_BYTES = 32


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(_ALGORITHM, password.encode(), salt, _ITERATIONS)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, dk_hex = stored_hash.split(":", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    dk_expected = bytes.fromhex(dk_hex)
    dk_actual = hashlib.pbkdf2_hmac(_ALGORITHM, password.encode(), salt, _ITERATIONS)
    return hmac.compare_digest(dk_actual, dk_expected)
