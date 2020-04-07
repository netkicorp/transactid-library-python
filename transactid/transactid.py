import base64
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from google.protobuf.message import DecodeError
from OpenSSL import crypto
from OpenSSL.crypto import X509StoreContextError

from typing import Tuple, Optional, List

from transactid import paymentrequest_pb2
from transactid.exceptions import InvalidSignatureException
from transactid.exceptions import DecodeException
from transactid.exceptions import MissingRootCertificateException
from transactid.exceptions import InvalidRootCertificateException

Output = Optional[List[Tuple[int, bytes]]]

payment_request_fields = ["payment_details_version", "pki_type", "pki_data", "serialized_payment_details", "signature"]
payment_details_fields = ["network", "outputs", "time", "expires", "memo", "payment_url", "merchant_data"]
payment_fields = ["merchant_data", "transactions", "refund_to", "memo"]
payment_ack_fields = ["payment", "memo"]
output_fields = ["amount", "script"]
invoice_request_fields = [
    "sender_public_key", "amount", "pki_type", "pki_data", "memo", "notification_url", "signature"
]


class TransactID:

    def __init__(
        self,
        private_key_pem: str,
        private_key_password: Optional[str] = None,
        certificate_pem: Optional[str] = None,
    ):
        self.created_invoice_request = None
        self.verified_invoice_request = None

        self.created_payment_details = None
        self.verified_payment_details = None

        self.created_payment_request = None
        self.verified_payment_request = None

        self.created_payment = None
        self.verified_payment = None

        self.created_payment_ack = None
        self.verified_payment_ack = None

        self.private_key_pem = private_key_pem
        self.private_key_password = private_key_password
        self.private_key, self.public_key_pem = self._set_keys()

        self.account_owner = None

        if certificate_pem is not None:
            self._load_certificate(certificate_pem)
            self.certificate_pem = str.encode(certificate_pem)
        else:
            self.certificate_pem = None

        self.root_cert_pem_files = None

    def set_account_owner(self, cert_private_key_data, primary_for_transaction=True):


    def _set_keys(self):
        """
        Sets the private and public keys for signing and sending objects.
        :return:
        """
        try:
            private_key = serialization.load_pem_private_key(
                str.encode(self.private_key_pem), password=self.private_key_password, backend=default_backend()
            )
        except ValueError:
            raise
        else:
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return private_key, public_key_pem

    def _build_certificate_store(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        certs_path = os.path.join(dir_path, "certs")
        pems = [f for f in os.listdir(certs_path) if f.endswith("pem")]

        certs = {}
        for pem_file in pems:
            with open(os.path.join(certs_path, pem_file), "r") as f:
                pem = f.read()

            cert = self._load_certificate(pem)
            root = cert.subject == cert.issuer
            if cert.issuer not in certs:
                if root:
                    certs[cert.issuer] = {"root": pem_file}
                else:
                    certs[cert.issuer] = {"intermediate": pem_file}
            else:
                root_available = certs[cert.issuer].get("root")
                intermediate_available = certs[cert.issuer].get("intermediate")
                if root_available and intermediate_available:
                    raise Exception(f"Too many pems for {cert.issuer}")
                if root_available:
                    if root:
                        raise Exception(f"Too many root pems for {cert.issuer}")
                    certs[cert.issuer]["intermediate"] = pem_file
                else:
                    if root:
                        certs[cert.issuer]["root"] = pem_file
                    else:
                        certs[cert.issuer]["intermediate"] = pem_file

        self.root_cert_pem_files = certs

    @staticmethod
    def _verify_chain_of_trust(cert_pem, trusted_cert_pems):

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        for trusted_cert_pem in trusted_cert_pems:
            trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
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

    @staticmethod
    def _load_certificate(cert_pem: str):
        try:
            cert = x509.load_pem_x509_certificate(str.encode(cert_pem), default_backend())
        except ValueError:
            raise
        return cert

    def create_invoice_request(
        self,
        amount: Optional[int] = None,
        pki_type: Optional[str] = "none",
        memo: Optional[str] = None,
        notification_url: Optional[str] = None,
    ):

        invoice_request = paymentrequest_pb2.InvoiceRequest()
        invoice_request.signature = b""
        invoice_request.pki_type = pki_type

        if amount:
            invoice_request.amount = amount
        if pki_type != "none":
            invoice_request.pki_data = self.certificate_pem
        if memo:
            invoice_request.memo = memo
        if notification_url:
            invoice_request.notification_url = notification_url

        self.created_invoice_request = invoice_request

        return self._prepare_invoice_request_for_sending()

    def create_payment_request(
        self,
        time_stamp: datetime,
        outputs: Output,
        memo: str,
        payment_url: str,
        merchant_data: bytes,
        expires: Optional[datetime] = None,
        network: str = "main",
        payment_details_version: int = 1,
        pki_type: Optional[str] = "none"
    ):
        if not outputs:
            outputs = ()

        payment_details = paymentrequest_pb2.PaymentDetails()

        time_epoch = int(time_stamp.timestamp())

        payment_details.network = network
        payment_details.time = time_epoch

        if expires:
            expires_epoch = int(expires.timestamp())
            payment_details.expires = expires_epoch

        for out in outputs:
            output = paymentrequest_pb2.Output()
            output.amount = out[0]
            output.script = out[1]
            payment_details.outputs.append(output)

        if memo:
            payment_details.memo = memo
        if payment_url:
            payment_details.payment_url = payment_url
        if merchant_data:
            payment_details.merchant_data = merchant_data

        self.created_payment_details = payment_details

        proto_payment_request = paymentrequest_pb2.PaymentRequest()

        if pki_type != "none":
            proto_payment_request.pki_data = self.certificate_pem

        proto_payment_request.pki_type = pki_type
        proto_payment_request.payment_details_version = payment_details_version
        proto_payment_request.serialized_payment_details = payment_details.SerializeToString(deterministic=True)

        self.created_payment_request = proto_payment_request

        return self._prepare_payment_request_for_sending()

    def create_payment(
        self,
        transactions: List[bytes],
        refund_to: Output,
        merchant_data: Optional[bytes] = None,
        memo: Optional[str] = None
    ):
        payment = paymentrequest_pb2.Payment()

        for t in transactions:
            payment.transactions.append(t)

        for out in refund_to:
            output = paymentrequest_pb2.Output()
            output.amount = out[0]
            output.script = out[1]
            payment.refund_to.append(output)

        if merchant_data:
            payment.merchant_data = merchant_data
        if memo:
            payment.memo = memo

        self.created_payment = payment

        return self.created_payment.SerializeToString(deterministic=True)

    def create_payment_ack(
        self,
        memo: Optional[str] = None
    ):
        if self.verified_payment is None:
            raise Exception("You need to have a verified Payment to acknowledge before creating the PaymentACK.")

        payment_ack = paymentrequest_pb2.PaymentACK()
        payment_ack.payment.CopyFrom(self.verified_payment)

        if memo:
            payment_ack.memo = memo

        self.created_payment_ack = payment_ack

        return self.created_payment_ack.SerializeToString(deterministic=True)

    def verify_invoice_request(self, invoice_request_binary: bytes):
        invoice_request = paymentrequest_pb2.InvoiceRequest()
        try:
            invoice_request.ParseFromString(invoice_request_binary)
        except DecodeError:
            raise DecodeException("Unable decode protobuf object.")

        if invoice_request.pki_type != "none":
            raw_cert = invoice_request.pki_data
            signature = base64.b64decode(invoice_request.signature)

            invoice_request.signature = b""
            invoice_request_serialized = invoice_request.SerializeToString(deterministic=True)
            message = self._create_hash(invoice_request_serialized)

            cert = x509.load_pem_x509_certificate(raw_cert, default_backend())
            public_key = cert.public_key()

            self._build_certificate_store()

            root_certs = self.root_cert_pem_files.get(cert.issuer)
            if not root_certs:
                raise MissingRootCertificateException(
                    f"Unable to find root certificate matching issuer: {cert.issuer}"
                )

            root_pems = [v for k, v in root_certs.items()]
            valid_root = self._verify_chain_of_trust(raw_cert, root_pems)

            if not valid_root:
                raise InvalidRootCertificateException("Certificate chain of provided certificate is invalid.")

            try:
                public_key.verify(
                    signature,
                    str.encode(message),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except InvalidSignature:
                raise InvalidSignatureException("Unable to verify signature.")

        self.verified_invoice_request = invoice_request

    def verify_payment_request(self, payment_request_binary: bytes):
        payment_request = paymentrequest_pb2.PaymentRequest()
        try:
            payment_request.ParseFromString(payment_request_binary)
        except DecodeError:
            raise DecodeException("Unable decode protobuf object.")

        if payment_request.pki_data != "none":
            raw_cert = payment_request.pki_data
            signature = base64.b64decode(payment_request.signature)

            payment_request.signature = b""
            payment_request_serialized = payment_request.SerializeToString(deterministic=True)
            message = self._create_hash(payment_request_serialized)

            cert = x509.load_pem_x509_certificate(raw_cert, default_backend())
            public_key = cert.public_key()

            self._build_certificate_store()

            root_certs = self.root_cert_pem_files.get(cert.issuer)
            if not root_certs:
                raise MissingRootCertificateException(
                    f"Unable to find root certificate matching issuer: {cert.issuer}"
                )

            root_pems = [v for k, v in root_certs.items()]
            valid_root = self._verify_chain_of_trust(raw_cert, root_pems)

            if not valid_root:
                raise InvalidRootCertificateException("Certificate chain of provided certificate is invalid.")

            try:
                public_key.verify(
                    signature,
                    str.encode(message),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except InvalidSignature:
                raise InvalidSignatureException("Unable to verify signature.")

        self.verified_payment_request = payment_request
        self._verify_payment_details(payment_request.serialized_payment_details)

    def _verify_payment_details(self, details_binary: bytes):
        payment_details = paymentrequest_pb2.PaymentDetails()
        try:
            payment_details.ParseFromString(details_binary)
        except DecodeError:
            raise DecodeException("Unable decode protobuf object.")

        self.verified_payment_details = payment_details

    def verify_payment(self, payment_binary: bytes):
        payment = paymentrequest_pb2.Payment()
        try:
            payment.ParseFromString(payment_binary)
        except DecodeError:
            raise DecodeException("Unable decode protobuf object.")

        self.verified_payment = payment

    def verify_payment_ack(self, payment_ack_binary: bytes):
        payment_ack = paymentrequest_pb2.PaymentACK()
        try:
            payment_ack.ParseFromString(payment_ack_binary)
        except DecodeError:
            raise DecodeException("Unable decode protobuf object.")

        self.verified_payment_ack = payment_ack

    def get_verified_payment_request(self):
        pr_dict = {}
        for field in payment_request_fields:
            try:
                self.verified_payment_request.HasField(field)
            except ValueError:
                continue
            else:
                pr_dict[field] = getattr(self.verified_payment_request, field)

        payment_details = self._get_verified_payment_details()
        pr_dict["payment_details"] = payment_details

        return pr_dict

    def get_verified_invoice_request(self):
        invoice_request_dict = {}
        for field in invoice_request_fields:
            try:
                self.verified_invoice_request.HasField(field)
            except ValueError:
                continue
            else:
                invoice_request_dict[field] = getattr(self.verified_invoice_request, field)
        return invoice_request_dict

    def get_verified_payment(self):
        payment_dict = {}
        for field in payment_fields:
            if field == "transactions":
                payment_dict[field] = getattr(self.verified_payment, field)
            elif field == "refund_to":
                payment_dict[field] = {
                    "amount": self.verified_payment.refund_to[0].amount,
                    "script": self.verified_payment.refund_to[0].script
                }
            else:
                try:
                    self.verified_payment.HasField(field)
                except ValueError:
                    continue
                else:
                    payment_dict[field] = getattr(self.verified_payment, field)
        return payment_dict

    def get_verified_payment_ack(self):
        payment_ack_dict = {"memo": getattr(self.verified_payment_ack, "memo"), "payment": {}}

        for field in payment_fields:
            if field == "transactions":
                payment_ack_dict["payment"][field] = getattr(self.verified_payment_ack.payment, field)
            elif field == "refund_to":
                payment_ack_dict["payment"][field] = {
                    "amount": self.verified_payment_ack.payment.refund_to[0].amount,
                    "script": self.verified_payment_ack.payment.refund_to[0].script
                }
            else:
                try:
                    self.verified_payment_ack.payment.HasField(field)
                except ValueError:
                    continue
                else:
                    payment_ack_dict["payment"][field] = getattr(self.verified_payment_ack.payment, field)
        return payment_ack_dict

    def _get_verified_payment_details(self):
        payment_details_dict = {}
        for field in payment_details_fields:
            if field == "outputs":
                payment_details_dict[field] = getattr(self.verified_payment_details, field)
            else:
                try:
                    self.verified_payment_details.HasField(field)
                except ValueError:
                    continue
                else:
                    payment_details_dict[field] = getattr(self.verified_payment_details, field)
        return payment_details_dict

    def _prepare_payment_request_for_sending(self):

        if self.created_payment_request is None:
            raise Exception("You need to create a PaymentRequest object first.")

        payment_request = paymentrequest_pb2.PaymentRequest()
        payment_request.CopyFrom(self.created_payment_request)

        payment_request.signature = b""

        payment_request_serialized = payment_request.SerializeToString(deterministic=True)

        payment_request_hash = self._create_hash(payment_request_serialized)
        signature = self._sign_message(payment_request_hash)

        payment_request.signature = base64.b64encode(signature)

        return payment_request.SerializeToString(deterministic=True)

    def _prepare_invoice_request_for_sending(self):

        if self.created_invoice_request is None:
            raise Exception("You need to create an InvoiceRequest first.")

        invoice_request = paymentrequest_pb2.InvoiceRequest()
        invoice_request.CopyFrom(self.created_invoice_request)

        if invoice_request.pki_type != "none":
            invoice_request.signature = b""

            invoice_request_serialized = invoice_request.SerializeToString(deterministic=True)

            invoice_request_hash = self._create_hash(invoice_request_serialized)
            signature = self._sign_message(invoice_request_hash)

            invoice_request.signature = base64.b64encode(signature)

        return invoice_request.SerializeToString(deterministic=True)

    def _sign_message(self, message):
        signature = self.private_key.sign(
            str.encode(message),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def _create_hash(message):
        pr_hash = hashlib.sha256()
        pr_hash.update(message)
        return pr_hash.hexdigest()
