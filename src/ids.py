# ============================================================
#  REMI Solar Services — AI Email Triage
#  Created by GOVERNYS (Niels Tilch — CTO)
# ============================================================
"""
ids.py — UUIDv7 generation (RFC 9562).

UUIDv7 values are time-ordered (48-bit Unix-millisecond prefix), which keeps
rows roughly insertion-ordered while still being globally unique and opaque.
These UUIDs are the identifiers used between the front-end and back-end;
integer primary keys remain internal to the database.
"""
import os
import time
import uuid as _uuid


def uuid7() -> str:
    """Return a new UUIDv7 as a string."""
    unix_ms = int(time.time() * 1000)
    rand = bytearray(os.urandom(10))
    b = bytearray(unix_ms.to_bytes(6, "big")) + rand
    b[6] = (b[6] & 0x0F) | 0x70          # version 7
    b[8] = (b[8] & 0x3F) | 0x80          # variant 10xx
    return str(_uuid.UUID(bytes=bytes(b)))
