"""Short-lived local mTLS identities for load-test regression fixtures."""

from pathlib import Path
import ssl
import subprocess
import tempfile


class LocalMtlsFixture:
    def __init__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="vaultlink-load-tls-")
        self.root = Path(self._temporary.name)

        def openssl(*args):
            subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)

        ca_key, ca_cert = self.root / "ca.key", self.root / "ca.crt"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=VaultLink local load test CA", "-keyout", ca_key, "-out", ca_cert)
        for name, extensions in (
            ("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"),
            ("client", "extendedKeyUsage=clientAuth\n"),
        ):
            key, request, certificate = (self.root / f"{name}.{suffix}" for suffix in ("key", "csr", "crt"))
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
                    "-keyout", key, "-out", request)
            extension_file = self.root / f"{name}.ext"
            extension_file.write_text(extensions)
            openssl("x509", "-req", "-in", request, "-CA", ca_cert, "-CAkey", ca_key,
                    "-CAcreateserial", "-out", certificate, "-days", "1", "-extfile", extension_file)

    def environment(self):
        return {
            "VAULTLINK_TLS_CLIENT_CERT": str(self.root / "client.crt"),
            "VAULTLINK_TLS_CLIENT_KEY": str(self.root / "client.key"),
            "VAULTLINK_TLS_SERVER_CA": str(self.root / "ca.crt"),
        }

    def wrap_server(self, server):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / "server.crt", self.root / "server.key")
        context.load_verify_locations(cafile=str(self.root / "ca.crt"))
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)

    def close(self):
        self._temporary.cleanup()
