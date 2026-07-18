#!/usr/bin/env python3
"""Expose a loopback-only VaultLink listener on a distinct container port."""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import stat
import threading
import tomllib
from pathlib import Path


MAX_CONFIG_BYTES = 1024 * 1024
MAX_REQUEST_HEADER_BYTES = 64 * 1024
FORWARDED_HEADERS = {b"connection", b"forwarded", b"x-forwarded-for"}


def parse_address(value: str) -> tuple[str, int]:
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
            raise ValueError(f"invalid socket address: {value!r}")
        host = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            raise ValueError(f"invalid socket address: {value!r}")
    ipaddress.ip_address(host)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid socket port: {port}")
    return host, port


def read_config_upstream(config_path: Path) -> tuple[str, int] | None:
    try:
        metadata = config_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CONFIG_BYTES:
            return None
        descriptor = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as config_file:
            config = tomllib.load(config_file)
        address = parse_address(config["server"]["listen_address"])
        if not ipaddress.ip_address(address[0]).is_loopback:
            return None
        return address
    except (KeyError, OSError, TomlDecodeError, TypeError, ValueError):
        return None


try:
    from tomllib import TOMLDecodeError as TomlDecodeError
except ImportError:  # pragma: no cover - Python 3.11+ always provides it.
    TomlDecodeError = ValueError


def connect_upstream(
    setup_upstream: tuple[str, int], config_path: Path
) -> socket.socket | None:
    candidates = [setup_upstream]
    configured = read_config_upstream(config_path)
    if configured is not None and configured not in candidates:
        candidates.append(configured)
    for address in candidates:
        try:
            upstream = socket.create_connection(address, timeout=2)
            upstream.settimeout(None)
            return upstream
        except OSError:
            continue
    return None


def relay(source: socket.socket, destination: socket.socket) -> None:
    try:
        while data := source.recv(65536):
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def read_request_headers(client: socket.socket, client_ip: str) -> bytes | None:
    """Remove client forwarding headers and add the address seen by this proxy."""
    request = bytearray()
    client.settimeout(5)
    try:
        while b"\r\n\r\n" not in request:
            chunk = client.recv(min(65536, MAX_REQUEST_HEADER_BYTES - len(request)))
            if not chunk:
                return None
            request.extend(chunk)
            if len(request) >= MAX_REQUEST_HEADER_BYTES:
                return None
    except OSError:
        return None
    finally:
        client.settimeout(None)

    header_end = request.index(b"\r\n\r\n")
    lines = request[:header_end].split(b"\r\n")
    if not lines or not lines[0]:
        return None

    sanitized = [lines[0]]
    for line in lines[1:]:
        name, separator, _ = line.partition(b":")
        if not separator or not name:
            return None
        if bytes(name.strip()).lower() not in FORWARDED_HEADERS:
            sanitized.append(line)
    sanitized.append(f"X-Forwarded-For: {client_ip}".encode("ascii"))
    # One request per upstream connection ensures every request that reaches
    # VaultLink has passed through the forwarding-header boundary above.
    sanitized.append(b"Connection: close")
    return b"\r\n".join(sanitized) + b"\r\n\r\n" + request[header_end + 4 :]


def handle_client(
    client: socket.socket,
    client_address: tuple[str, int],
    setup_upstream: tuple[str, int],
    config_path: Path,
) -> None:
    with client:
        request = read_request_headers(client, client_address[0])
        if request is None:
            return
        upstream = connect_upstream(setup_upstream, config_path)
        if upstream is None:
            return
        with upstream:
            try:
                upstream.sendall(request)
            except OSError:
                return
            outbound = threading.Thread(
                target=relay,
                args=(client, upstream),
                daemon=True,
            )
            outbound.start()
            relay(upstream, client)
            outbound.join(timeout=1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--setup-upstream", required=True)
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args()
    listen = parse_address(arguments.listen)
    setup_upstream = parse_address(arguments.setup_upstream)
    if not ipaddress.ip_address(setup_upstream[0]).is_loopback:
        parser.error("--setup-upstream must be a loopback address")

    family = socket.AF_INET6 if ipaddress.ip_address(listen[0]).version == 6 else socket.AF_INET
    with socket.create_server(listen, family=family) as listener:
        while True:
            client, client_address = listener.accept()
            threading.Thread(
                target=handle_client,
                args=(client, client_address, setup_upstream, arguments.config),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
