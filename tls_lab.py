"""Create a local test CA, sign a localhost certificate, and verify a real TLS exchange."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import ssl
import subprocess

def openssl(*arguments: str) -> str:
    return subprocess.run(["openssl", *map(str, arguments)], check=True, capture_output=True, text=True).stdout

def create_material(directory: Path) -> None:
    # Refuse existing folders so a repeat run cannot overwrite someone's keys.
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "7",
            "-subj", "/CN=Local Study CA", "-keyout", directory / "ca.key", "-out", directory / "ca.crt",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
            "-keyout", directory / "server.key", "-out", directory / "server.csr")
    extension = directory / "server.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    openssl("x509", "-req", "-in", directory / "server.csr", "-CA", directory / "ca.crt",
            "-CAkey", directory / "ca.key", "-CAcreateserial", "-out", directory / "server.crt",
            "-days", "7", "-sha256", "-extfile", extension)
    for name in ["ca.key", "server.key"]:
        (directory / name).chmod(0o600)

def receive_line(connection: ssl.SSLSocket) -> bytes:
    chunks = bytearray()
    while len(chunks) < 1024:
        chunk = connection.recv(1)
        if not chunk:
            raise ConnectionError("Peer closed before finishing the message.")
        chunks.extend(chunk)
        if chunk == b"\n":
            return bytes(chunks)
    raise ValueError("Demo message is too large.")

def exchange(directory: Path, hostname: str = "localhost", trust_local_ca: bool = True) -> dict:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(directory / "server.crt", directory / "server.key")
    client_context = ssl.create_default_context(cafile=str(directory / "ca.crt") if trust_local_ca else None)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        def serve():
            try:
                raw, _ = listener.accept()
                with raw:
                    raw.settimeout(5)
                    with server_context.wrap_socket(raw, server_side=True) as secure:
                        secure.sendall(receive_line(secure))
            except ssl.SSLError:
                return "Client rejected the certificate."
            return "Exchange completed."
        with ThreadPoolExecutor(max_workers=1) as pool:
            job = pool.submit(serve)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with client_context.wrap_socket(raw, server_hostname=hostname) as secure:
                    secure.sendall(b"Hello through verified TLS!\n")
                    result = {"tls_version": secure.version(), "cipher": secure.cipher()[0],
                              "reply": receive_line(secure).decode().strip(),
                              "hostname_verified": hostname}
            job.result(timeout=5)
            return result

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("certificates"))
    args = parser.parse_args()
    try:
        if not args.directory.exists():
            create_material(args.directory)
        print(json.dumps(exchange(args.directory), indent=2))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"Error: {error}\n")

if __name__ == "__main__":
    raise SystemExit(main())
