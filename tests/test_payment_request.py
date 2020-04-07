import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto
from OpenSSL.crypto import X509StoreContextError

from transactid import transactid
from transactid import paymentrequest_pb2
from transactid.exceptions import InvalidSignatureException
from transactid.exceptions import DecodeException


class TestPaymentRequests(unittest.TestCase):

    def verify_chain_of_trust(self, cert_pem):

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, str.encode(cert_pem))

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()

        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, str.encode(self.root_certificate_pem))
        store.add_cert(trusted_cert)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(store, certificate)
        # Returns None if certificate can be validated
        try:
            result = store_ctx.verify_certificate()
        except X509StoreContextError:
            result = False

        if result is None:
            return True
        else:
            return False

    def setUp(self) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        root_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.private_key_pem = str(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), "utf-8")

        root_subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetkiTransactID"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"TransactIDRootTester"),
        ])

        root_cert = x509.CertificateBuilder().subject_name(
            root_subject
        ).issuer_name(
            issuer
        ).public_key(
            root_private_key.public_key()
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
        ).sign(root_private_key, hashes.SHA256(), default_backend())

        subject = x509.Name([
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
        self.root_certificate_pem = str(root_cert.public_bytes(serialization.Encoding.PEM), "utf-8")

    def test_create_payment_request_with_signature(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )
        pki_type = "x509+sha256"
        memo = "Lion"
        payment_url = "https://www.youtube.com/watch?v=6oanIo_2Z4Q"
        merchant_data = b"They are queens."
        output_amount = 2400
        output_script = b"rawr"
        outputs = [(output_amount, output_script)]

        serialized_payment_request = transact.create_payment_request(
            time_stamp=datetime.datetime.now(),
            outputs=outputs,
            memo=memo,
            payment_url=payment_url,
            merchant_data=merchant_data,
            pki_type=pki_type
        )

        self.assertEqual(transact.created_payment_details.memo, memo)
        self.assertEqual(transact.created_payment_details.payment_url, payment_url)
        self.assertEqual(transact.created_payment_details.merchant_data, merchant_data)
        self.assertEqual(transact.created_payment_details.outputs[0].amount, output_amount)
        self.assertEqual(transact.created_payment_details.outputs[0].script, output_script)
        self.assertEqual(transact.created_payment_request.pki_type, pki_type)

    def test_create_payment_request_without_signature(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
        )
        pki_type = "none"
        memo = "Not Sorry"
        payment_url = "https://www.youtube.com/watch?v=FwsUHHiPcRA"
        merchant_data = b"They too are queens."
        output_amount = 2600
        output_script = b"ace"
        outputs = [(output_amount, output_script)]

        serialized_payment_request = transact.create_payment_request(
            time_stamp=datetime.datetime.now(),
            outputs=outputs,
            memo=memo,
            payment_url=payment_url,
            merchant_data=merchant_data,
            pki_type=pki_type
        )

        self.assertEqual(transact.created_payment_details.memo, memo)
        self.assertEqual(transact.created_payment_details.payment_url, payment_url)
        self.assertEqual(transact.created_payment_details.merchant_data, merchant_data)
        self.assertEqual(transact.created_payment_details.outputs[0].amount, output_amount)
        self.assertEqual(transact.created_payment_details.outputs[0].script, output_script)
        self.assertEqual(transact.created_payment_request.pki_type, pki_type)
        self.assertEqual(transact.created_payment_request.pki_data, b"")

    def test_parsing_payment_request(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        pki_type = "x509+sha256"
        memo = "Guerilla"
        payment_url = "https://www.youtube.com/watch?v=wVMeNl4UfIE"
        merchant_data = b"It's a miracle."
        output_amount = 2400
        output_script = b"Seunghee"
        outputs = [(output_amount, output_script)]

        serialized_payment_request = transact.create_payment_request(
            time_stamp=datetime.datetime.now(),
            outputs=outputs,
            memo=memo,
            payment_url=payment_url,
            merchant_data=merchant_data,
            pki_type=pki_type
        )

        transact2 = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        transact2._verify_chain_of_trust = self.verify_chain_of_trust

        transact2.verify_payment_request(serialized_payment_request)

        verified_data = transact2.get_verified_payment_request()

        self.assertEqual(pki_type, verified_data["pki_type"])
        self.assertEqual(memo, verified_data["payment_details"]["memo"])
        self.assertEqual(payment_url, verified_data["payment_details"]["payment_url"])
        self.assertEqual(transact.certificate_pem, verified_data["pki_data"])

    def test_parsing_invalid_signature(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        pki_type = "x509+sha256"
        memo = "Moonlight"
        payment_url = "https://www.youtube.com/watch?v=OlI8Ly3sxvI"
        merchant_data = b"LTC"
        output_amount = 2400
        output_script = b"Lovelinus"
        outputs = [(output_amount, output_script)]

        serialized_payment_request = transact.create_payment_request(
            time_stamp=datetime.datetime.now(),
            outputs=outputs,
            memo=memo,
            payment_url=payment_url,
            merchant_data=merchant_data,
            pki_type=pki_type
        )

        proto_request = paymentrequest_pb2.PaymentRequest()
        proto_request.ParseFromString(serialized_payment_request)
        proto_request.pki_type = "Oh Mijoo"

        serialized_proto_request = proto_request.SerializeToString(deterministic=True)

        transact._verify_chain_of_trust = self.verify_chain_of_trust

        with self.assertRaises(InvalidSignatureException) as context:
            transact.verify_payment_request(serialized_proto_request)

        self.assertTrue("Unable to verify signature." in str(context.exception))

    def test_parsing_invalid_protobuf(self):
        transact = transactid.TransactID(
            private_key_pem=self.private_key_pem,
            certificate_pem=self.certificate_pem
        )

        with self.assertRaises(DecodeException) as context:
            transact.verify_payment_request(b"Seunghee")

        self.assertTrue("Unable decode protobuf object." in str(context.exception))


if __name__ == '__main__':
    unittest.main()
