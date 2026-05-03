"""
Mock LDAP server for local development.

Speaks just enough of the LDAP wire protocol (RFC 4511, BER-encoded)
to satisfy the ldap3 client library used by checkpoint.py. Returns
empty search results for every query so the application can start
without connectivity to Whitepages or GTAD.

Run standalone:
    poetry run python ldap_mock.py [--port PORT]

Serves both anonymous binds (Whitepages) and simple authenticated
binds (GTAD) on the same port.
"""

import argparse
import logging
import socket
import threading
from typing import Tuple

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("ldap_mock")

# ---------------------------------------------------------------------------
# Minimal BER / LDAP helpers
# ---------------------------------------------------------------------------

# LDAP protocol tags (application class, constructed where noted)
BIND_REQUEST = 0x60
BIND_RESPONSE = 0x61
UNBIND_REQUEST = 0x42
SEARCH_REQUEST = 0x63
SEARCH_RESULT_DONE = 0x65
EXTENDED_REQUEST = 0x77
EXTENDED_RESPONSE = 0x78


def ber_read_tag_length(data: bytes, offset: int) -> Tuple[int, int, int]:
    """Return (tag, length, new_offset) for one BER TLV at *offset*."""
    if offset >= len(data):
        raise ValueError("no data")
    tag = data[offset]
    offset += 1

    if offset >= len(data):
        raise ValueError("truncated length")

    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ValueError("indefinite length not supported")
    else:
        num_bytes = first & 0x7F
        if offset + num_bytes > len(data):
            raise ValueError("truncated long length")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    return tag, length, offset


def ber_encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def ber_encode_integer(value: int) -> bytes:
    """Encode a BER INTEGER."""
    if value == 0:
        payload = b"\x00"
    else:
        byte_len = (value.bit_length() + 8) // 8
        payload = value.to_bytes(byte_len, "big", signed=True)
    return b"\x02" + ber_encode_length(len(payload)) + payload


def ber_encode_octet_string(value: bytes) -> bytes:
    """Encode a BER OCTET STRING."""
    return b"\x04" + ber_encode_length(len(value)) + value


def ber_encode_enum(value: int) -> bytes:
    """Encode a BER ENUMERATED value."""
    payload = value.to_bytes(1, "big")
    return b"\x0a" + ber_encode_length(len(payload)) + payload


def ber_encode_sequence(payload: bytes) -> bytes:
    """Encode a BER SEQUENCE."""
    return b"\x30" + ber_encode_length(len(payload)) + payload


def ber_build_ldap_message(message_id: int, op_tag: int, op_payload: bytes) -> bytes:
    """Wrap an LDAP operation in a top-level LDAPMessage SEQUENCE."""
    inner = ber_encode_integer(message_id)
    inner += bytes([op_tag]) + ber_encode_length(len(op_payload)) + op_payload
    return ber_encode_sequence(inner)


def ber_read_integer(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a BER INTEGER, return (value, new_offset)."""
    tag, length, offset = ber_read_tag_length(data, offset)
    if tag != 0x02:
        raise ValueError(f"expected INTEGER (0x02), got 0x{tag:02x}")
    value = int.from_bytes(data[offset : offset + length], "big", signed=True)
    return value, offset + length


# ---------------------------------------------------------------------------
# LDAP response builders
# ---------------------------------------------------------------------------

RESULT_SUCCESS = 0


def ldap_result_payload(
    result_code: int = RESULT_SUCCESS,
    matched_dn: bytes = b"",
    diagnostic: bytes = b"",
) -> bytes:
    """Encode the common LDAPResult fields."""
    return (
        ber_encode_enum(result_code)
        + ber_encode_octet_string(matched_dn)
        + ber_encode_octet_string(diagnostic)
    )


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------


def recvall(sock: socket.socket, n: int) -> bytes:
    """Receive exactly *n* bytes or raise."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed")
        buf.extend(chunk)
    return bytes(buf)


def read_ldap_message(sock: socket.socket) -> bytes:
    """Read one complete BER-encoded LDAP message from the socket."""
    header = recvall(sock, 2)
    if header[0] != 0x30:
        raise ValueError(f"expected SEQUENCE tag 0x30, got 0x{header[0]:02x}")

    first = header[1]
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ValueError("indefinite length not supported")
    else:
        num_bytes = first & 0x7F
        length_bytes = recvall(sock, num_bytes)
        length = int.from_bytes(length_bytes, "big")
        header = header + length_bytes

    body = recvall(sock, length)
    return header + body


def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """Handle one LDAP client connection."""
    logger.info("connection from %s", addr)
    try:
        while True:
            try:
                raw = read_ldap_message(conn)
            except (ConnectionError, ValueError):
                break

            _, _, offset = ber_read_tag_length(raw, 0)
            message_id, offset = ber_read_integer(raw, offset)

            op_tag = raw[offset]
            _, op_len, _ = ber_read_tag_length(raw, offset)

            logger.debug("msg %d  op=0x%02x  len=%d", message_id, op_tag, op_len)

            if op_tag == BIND_REQUEST:
                resp = ber_build_ldap_message(message_id, BIND_RESPONSE, ldap_result_payload())
                conn.sendall(resp)

            elif op_tag == SEARCH_REQUEST:
                resp = ber_build_ldap_message(message_id, SEARCH_RESULT_DONE, ldap_result_payload())
                conn.sendall(resp)

            elif op_tag == UNBIND_REQUEST:
                break

            elif op_tag == EXTENDED_REQUEST:
                resp = ber_build_ldap_message(message_id, EXTENDED_RESPONSE, ldap_result_payload())
                conn.sendall(resp)

            else:
                logger.warning("unhandled op 0x%02x – ignoring", op_tag)
    finally:
        conn.close()
        logger.info("closed %s", addr)


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def serve(host: str = "127.0.0.1", port: int = 10389) -> None:
    """Run the mock LDAP server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(8)
        logger.info("mock LDAP listening on %s:%d", host, port)
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock LDAP server")
    parser.add_argument("--port", type=int, default=10389)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args = parser.parse_args()
    serve(host=args.host, port=args.port)
