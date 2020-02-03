# -*- coding: utf-8 -*-
from cryptography.exceptions import InvalidSignature
from google.protobuf.message import DecodeError


class DecodeException(DecodeError):
    """Custom exception for protobuf decoding exceptions."""
    pass


class InvalidSignatureException(InvalidSignature):
    """Custom exception for invalid signature exceptions."""
    pass

