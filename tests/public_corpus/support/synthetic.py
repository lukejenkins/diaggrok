"""Public synthetic frame builders (Chunk 5). Every value is fabricated;
this module imports no capture data and cites no path. It is the ONLY
sanctioned input-byte source for public-corpus fixtures (risk-tier D10)."""
import struct

def pack(fmt: str, *values) -> bytes:
    return struct.pack(fmt, *values)

def diag_frame(code: int, version: int, payload: bytes) -> bytes:
    """A minimal DIAG log payload body: version byte + parser payload.
    (The log-code header is applied by the parser harness, matching how the
    per-log parsers are called with the post-header body.)"""
    return bytes([version & 0xFF]) + payload
