# Local TLS Lab — Python / OpenSSL / X.509

A reconstruction and extension of the supplied **SSL exercise 1: Create certificates** and the certificate concepts in **OpenVPN Theory and Practical**. New code, October 2026.

The SSL PDF supplies the private-key → CSR → signed-certificate command sequence. This implementation automates that workflow with a local CA, a localhost Subject Alternative Name, certificate-chain verification and a real encrypted loopback exchange.

## Run

Python 3.12+ and the `openssl` command. No Python packages.

```sh
python tls_lab.py
python -m unittest discover -s tests -v
```

The first run creates a `certificates/` folder with seven-day test certificates. Later runs reuse that folder. Use `--directory another-new-folder` to create another independent lab. Existing files are never overwritten by the creation function.

## What happens

1. Generate a local test CA and private key.
2. Generate a server key and certificate signing request.
3. Sign a leaf certificate for `localhost` and `127.0.0.1`.
4. Start a one-message TLS listener on `127.0.0.1` with an ephemeral port.
5. Connect using a client context that trusts only the supplied lab CA and verifies the hostname.
6. Echo a message through the authenticated encrypted connection, then stop.

Five tests include successful TLS, wrong-host rejection, unknown-CA rejection, OpenSSL verification and overwrite prevention. Private key files use mode `0600` in a newly created `0700` directory on Unix. Keys are unencrypted, short-lived lab material and are excluded from Git.

This does not install a CA into the operating system, alter browser trust, open public interfaces or create a VPN. The VPN PDF informs the CA/identity concepts; no claim of a working OpenVPN tunnel is made.

Primary reference: [Python ssl documentation](https://docs.python.org/3/library/ssl.html).
