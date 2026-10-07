from datetime import datetime, timedelta
from pathlib import Path
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


OUTPUT_DIR = Path("samples")

KEY_FILE = OUTPUT_DIR / "server.key"
CERT_FILE = OUTPUT_DIR / "server.crt"


def generate_certificate():
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("[+] Generating private key...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "127.0.0.1",
        ),
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(
            private_key.public_key()
        )
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            datetime.utcnow()
        )
        .not_valid_after(
            datetime.utcnow()
            + timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(
                    ipaddress.ip_address(
                        "127.0.0.1"
                    )
                ),
            ]),
            critical=False,
        )
        .sign(
            private_key,
            hashes.SHA256(),
        )
    )

    KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    CERT_FILE.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )

    print("[+] Certificate generated.")
    print(f"[+] Private key : {KEY_FILE}")
    print(f"[+] Certificate : {CERT_FILE}")


if __name__ == "__main__":
    generate_certificate()