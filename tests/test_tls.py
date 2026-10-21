from pathlib import Path
import ssl
import stat
import tempfile
import unittest
from tls_lab import create_material, exchange, openssl

class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name) / "certificates"
        create_material(cls.directory)
    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_real_tls_exchange_verifies_the_local_certificate(self):
        result = exchange(self.directory)
        self.assertIn(result["tls_version"], ["TLSv1.2", "TLSv1.3"])
        self.assertEqual(result["reply"], "Hello through verified TLS!")

    def test_wrong_hostname_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError): exchange(self.directory, "wrong.example.test")

    def test_untrusted_issuer_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError): exchange(self.directory, trust_local_ca=False)

    def test_openssl_chain_check_and_private_file_permissions(self):
        result = openssl("verify", "-CAfile", self.directory / "ca.crt", "-verify_hostname", "localhost", self.directory / "server.crt")
        self.assertIn(": OK", result)
        self.assertEqual(stat.S_IMODE((self.directory / "server.key").stat().st_mode), 0o600)

    def test_creation_cannot_overwrite_existing_material(self):
        before = (self.directory / "server.key").read_bytes()
        with self.assertRaises(FileExistsError): create_material(self.directory)
        self.assertEqual((self.directory / "server.key").read_bytes(), before)

if __name__ == "__main__": unittest.main()
