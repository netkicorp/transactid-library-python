import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from transactid import transactid
from transactid.exceptions import DecodeException


class TestPaymentACKs(unittest.TestCase):

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

    def test_create_payment_ack(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem
        )

        payment_memo = "HIP"
        transactions = [b"Mamamoo"]
        merchant_data = b"Solar is queen"
        output_amount = 2400
        output_script = b"https://www.youtube.com/watch?v=KhTeiaCezwM"
        outputs = [(output_amount, output_script)]

        serialized_payment = transact.create_payment(
            transactions=transactions,
            refund_to=outputs,
            memo=payment_memo,
            merchant_data=merchant_data,
        )
        transact.verify_payment(serialized_payment)

        payment_ack_memo = "Wheein wrecks biases though"
        serialized_payment_ack = transact.create_payment_ack(memo=payment_ack_memo)

        self.assertEqual(transact.created_payment_ack.memo, payment_ack_memo)
        self.assertEqual(transact.created_payment_ack.payment, transact.created_payment)

    def test_parsing_payment_ack(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem
        )

        memo = "Eraser"
        transactions = [b"Dreamcatcher"]
        merchant_data = b"Siyeon"
        output_amount = 2400
        output_script = b"https://www.youtube.com/watch?v=Q5ozyxgEcws"
        outputs = [(output_amount, output_script)]

        serialized_payment = transact.create_payment(
            transactions=transactions,
            refund_to=outputs,
            memo=memo,
            merchant_data=merchant_data,
        )
        transact.verify_payment(serialized_payment)

        payment_ack_memo = "We really need a full cover of this song."
        serialized_payment_ack = transact.create_payment_ack(memo=payment_ack_memo)

        transact2 = transactid.TransactID(
            private_key_pem=self.private_key_pem
        )

        transact2.verify_payment_ack(serialized_payment_ack)

        verified_data = transact2.get_verified_payment_ack()
        self.assertEqual(transactions, verified_data["payment"]["transactions"])
        self.assertEqual(memo, verified_data["payment"]["memo"])
        self.assertEqual(merchant_data, verified_data["payment"]["merchant_data"])
        self.assertEqual(outputs, [(verified_data["payment"]["refund_to"]["amount"],
                                    verified_data["payment"]["refund_to"]["script"])])
        self.assertEqual(payment_ack_memo, verified_data["memo"])

    def test_parsing_invalid_protobuf(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        with self.assertRaises(DecodeException) as context:
            transact.verify_payment(b"Yein")

        self.assertTrue("Unable decode protobuf object." in str(context.exception))


if __name__ == '__main__':
    unittest.main()
