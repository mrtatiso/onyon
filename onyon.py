#!/usr/bin/env python3
"""onyon: syvox + onion → another onion, always the same for the same pair.

    $ echo clave | vox <salt> | onyon seal <real.onion>      → the onion to store
    $ echo clave | vox <salt> | onyon open <stored.onion>    → the onion it hides

    >>> from onyon import seal, open_
    >>> stored = seal(syvox, real)
    >>> open_(syvox, stored) == real
    True

onyon never sees a key or a salt: it receives a syvox (any 80 digits, usually
from vox) and an onion. The syvox is read from stdin, never from an argument,
so it does not end up in the shell history.

Every syvox opens every stored onion into a valid v3 onion: right checksum,
version 3, and a public key that is a real ed25519 point of prime order, the
kind Tor accepts. A wrong syvox gives an onion indistinguishable from any
other, uniformly chosen among all valid v3 keys.

v1: k = shake_256("onyon1|" + 80 digits) mod ℓ.  seal: P + k·B.  open: P − k·B.
Adding a multiple of the base point keeps the key inside the group, so the
result is always valid. Changing any of this would be v2.
"""
import base64
import hashlib
import sys

__version__ = "1.0.0"
__all__ = ["seal", "open_", "parse", "address"]

DIGITS = 80

# ---------- ed25519 (RFC 8032), only what onyon needs ----------

Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, Q - 2, Q) % Q
SQRT_M1 = pow(2, (Q - 1) // 4, Q)
ZERO = (0, 1, 1, 0)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % Q
    b = (y1 + x1) * (y2 + x2) % Q
    c = t1 * 2 * D * t2 % Q
    d = z1 * 2 * z2 % Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % Q, g * h % Q, f * g % Q, e * h % Q)


def _mul(k, p):
    r = ZERO
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _neg(p):
    x, y, z, t = p
    return (-x % Q, y, z, -t % Q)


def _is_zero(p):
    x, y, z, _ = p
    return x % Q == 0 and (y - z) % Q == 0


def _decode(b: bytes):
    """A point from 32 bytes, or None if it is not a canonical point."""
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= Q:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q:
        x = x * SQRT_M1 % Q
    if (x * x - x2) % Q:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = Q - x
    return (x, y, 1, x * y % Q)


def _encode(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, Q - 2, Q)
    x, y = x * zi % Q, y * zi % Q
    return (y | (x & 1) << 255).to_bytes(32, "little")


B = _decode((4 * pow(5, Q - 2, Q) % Q).to_bytes(32, "little"))

# ---------- onion v3 addresses ----------


def _checksum(pub: bytes) -> bytes:
    return hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2]


def address(pub: bytes) -> str:
    """The v3 onion address of a 32-byte ed25519 public key."""
    return base64.b32encode(pub + _checksum(pub) + b"\x03").decode().lower() + ".onion"


def parse(onion: str):
    """The point inside a valid v3 onion. ValueError if it is not one."""
    s = onion.strip().lower()
    s = s[:-6] if s.endswith(".onion") else s
    try:
        raw = base64.b32decode(s.upper())
    except Exception:
        raise ValueError("not a v3 onion: bad base32") from None
    if len(raw) != 35 or raw[34] != 3:
        raise ValueError("not a v3 onion: wrong length or version")
    pub = raw[:32]
    if raw[32:34] != _checksum(pub):
        raise ValueError("not a v3 onion: bad checksum")
    pt = _decode(pub)
    if pt is None or _is_zero(pt) or not _is_zero(_mul(L, pt)):
        raise ValueError("not a v3 onion: not a valid ed25519 key")
    return pt

# ---------- onyon ----------


def _k(syvox: str) -> int:
    digits = "".join(c for c in syvox if c in "0123456789")
    if len(digits) != DIGITS:
        raise ValueError(f"syvox must have {DIGITS} digits, not {len(digits)}")
    return int.from_bytes(hashlib.shake_256(b"onyon1|" + digits.encode()).digest(64), "little") % L


def seal(syvox: str, onion: str) -> str:
    """The onion to store so that open_ with this syvox gives back `onion`."""
    return address(_encode(_add(parse(onion), _mul(_k(syvox), B))))


def open_(syvox: str, onion: str) -> str:
    """The onion that this stored onion hides under this syvox."""
    return address(_encode(_add(parse(onion), _neg(_mul(_k(syvox), B)))))

# ---------- terminal ----------

USAGE = """usage:
  onyon seal <onion>    the onion to store
  onyon open <onion>    the onion it hides
The syvox comes through stdin, for example: echo clave | vox <salt> | onyon open <onion>"""


def main(args=None) -> int:
    args = sys.argv[1:] if args is None else args
    if len(args) != 2 or args[0] not in ("seal", "open") or sys.stdin.isatty():
        print(USAGE, file=sys.stderr)
        return 2
    try:
        print((seal if args[0] == "seal" else open_)(sys.stdin.readline().strip(), args[1]))
    except ValueError as e:
        print(f"onyon: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
