import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from transactid import transactid
from transactid import paymentrequest_pb2
from transactid.exceptions import InvalidSignatureException
from transactid.exceptions import DecodeException


class TestInvoiceRequests(unittest.TestCase):

    def setUp(self) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.private_key_pem = str(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), "utf-8")

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetkiTransactID"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"TransactIDTester"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(private_key, hashes.SHA256(), default_backend())

        self.certificate_pem = str(cert.public_bytes(serialization.Encoding.PEM), "utf-8")

    def test_creating_invoice_request_with_signature(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )
        pki_type = "x509+sha256"
        memo = "Stan LOONA"
        notification_url = "http://loonatheworld.com"

        serialized_invoice_request = transact.create_invoice_request(
            amount=24000,
            pki_type=pki_type,
            memo=memo,
            notification_url=notification_url
        )

        self.assertIsNotNone(transact.created_invoice_request)
        self.assertEqual(transact.created_invoice_request.pki_type, pki_type)
        self.assertEqual(transact.created_invoice_request.pki_data, transact.certificate_pem)
        self.assertEqual(transact.created_invoice_request.memo, memo)
        self.assertEqual(transact.created_invoice_request.notification_url, notification_url)

    def test_creating_invoice_request_without_signature(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
        )
        memo = "Stan LOONA"
        notification_url = "http://loonatheworld.com"

        serialized_invoice_request = transact.create_invoice_request(
            amount=24000,
            memo=memo,
            notification_url=notification_url
        )

        self.assertIsNotNone(transact.created_invoice_request)
        self.assertEqual(transact.created_invoice_request.pki_type, "none")
        self.assertEqual(transact.created_invoice_request.pki_data, b"")
        self.assertEqual(transact.created_invoice_request.memo, memo)
        self.assertEqual(transact.created_invoice_request.notification_url, notification_url)

    def test_parsing_invoice_request(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        pki_type = "x509+sha256"
        memo = "Stan LOONA"
        notification_url = "http://loonatheworld.com"

        serialized_invoice_request = transact.create_invoice_request(
            amount=24000,
            pki_type=pki_type,
            memo=memo,
            notification_url=notification_url
        )

        transact2 = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        transact2.verify_invoice_request(serialized_invoice_request)

        verified_data = transact2.get_verified_invoice_request()

        self.assertEqual(pki_type, verified_data["pki_type"])
        self.assertEqual(memo, verified_data["memo"])
        self.assertEqual(notification_url, verified_data["notification_url"])
        self.assertEqual(transact.certificate_pem, verified_data["pki_data"])

    def test_parsing_invalid_signature(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        pki_type = "x509+sha256"
        memo = "Stan LOONA"
        notification_url = "http://loonatheworld.com"

        serialized_invoice_request = transact.create_invoice_request(
            amount=24000,
            pki_type=pki_type,
            memo=memo,
            notification_url=notification_url
        )

        proto_request = paymentrequest_pb2.InvoiceRequest()
        proto_request.ParseFromString(serialized_invoice_request)
        proto_request.memo = "Mamamoo is cool too."

        serialized_proto_request = proto_request.SerializeToString(deterministic=True)

        with self.assertRaises(InvalidSignatureException) as context:
            transact.verify_invoice_request(serialized_proto_request)

        self.assertTrue("Unable to verify signature." in str(context.exception))

    def test_parsing_invalid_protobuf(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        with self.assertRaises(DecodeException) as context:
            transact.verify_invoice_request(b"attack my heart")

        self.assertTrue("Unable decode protobuf object." in str(context.exception))


if __name__ == '__main__':
    unittest.main()
