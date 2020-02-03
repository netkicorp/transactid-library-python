TransactID Library Python Edition

This library is a wrapper for using [BIP70][1] and [BIP75][2]

There are three main method types that you'll use: create_\*, verify_\*, and get_\*.

The options for each of these methods was pulled directly from the code and include type hints.  Things to keep 
in mind when going through this document:
* Optional[] means a single item of the type of object inside the brackets is optional and not required.
* List[type] means that you need to provide a list of items of the specified type.
* type means the usual, provide a single item of that type.

## General Usage

When instantiating the class you'll need a private key PEM and optionally a certificate PEM.  Both as
standard str types.  Certificate will only be needed when creating signed objects.  If you aren't 
signing or creating objects you won't need that but private key PEM is always required.

    from transactid import TransactID
    transact = TransactID(private_key_pem=private_pem, certificate_pem=cert_pem)

## Invoice Request

Please refer to the [BIP75][2] documentation for detailed requirements for a InvoiceRequest.  When it comes 
to using this library to create one you'll need to provide the following:

* amount: Optional[int]  # amount is integer-number-of-satoshis
* pki_type: Optional[str]  # Currently only x509+sha256 and the string none are supported.
* memo: Optional[str]
* notification_url: Optional[str]

*Note:* while everything is technically optional it's not recommended to leave everything blank.  See [BIP75][2] for 
full details.

Create an object for sending like so:

    serialized_invoice_request = transact.create_invoice_request(
        amount=amount,
        pki_type=pki_type,
        memo=memo,
        notification_url=notification_url
    )

This will provide you with a serialized binary string that you can then send to someone you would like to send 
money to.

When you are on the receiving end of one of those binary strings you can do the following to validate 
the signature and parse one:

    from transactid.exceptions import InvalidSignatureException
    from transactid.exceptions import DecodeException

    try:
        transact.verify_invoice_request(serialized_invoice_request)
    except InvalidSignatureException:
        <let sender know the signature was invalid>
    except DecodeException:
        <let sendiner know there was a problem with the porotobuf object they sent over>
    else:
        <take data they sent you and respond appropriately>

If there are no exceptions then we were able to parse the protobuf object and validate the signature.

To access the data from the InvoiceRequest just do:

    invoice_request = transact.get_verified_invoice_request()

And that will return a dictionary with all of the fields of the InvoiceRequest and the values that were 
filled in.

## Payment Request

Please refer to the [BIP70][1] documentation for detailed requirements for a PaymentRequest. Please note we are combining
 the PaymentDetails and PaymentRequests objects for easy of use. When it comes to using this library to create 
 one you'll need to provide the following:

* time_stamp: datetime
* outputs: List[(int, bytes)]  # int: amount, bytes: script (see [BIP70][1] details for more information on scripts)
* memo: str
* payment_url: str
* merchant_data: bytes
* expires: Optional[datetime]
* pki_type: Optional[str]
* network: str, defaults to "main"
* payment_details_version: int, defaults to 1

Create an object for sending like so:

    serialized_payment_request = transact.create_payment_request(
        time_stamp=datetime.datetime.now(),
        outputs=[(amount, script)],
        memo=memo,
        payment_url=payment_url,
        merchant_data=merchant_data,
        pki_type=pki_type
    )

This will provide you with a serialized binary string that you can then send to someone whom you want to give you 
money.

When you are on the receiving end of one of those binary strings you can do the following to validate 
the signature and parse one:

    from transactid.exceptions import InvalidSignatureException
    from transactid.exceptions import DecodeException

    try:
        transact.verify_payment_request(serialized_invoice_request)
    except InvalidSignatureException:
        <let sender know the signature was invalid>
    except DecodeException:
        <let sendiner know there was a problem with the porotobuf object they sent over>
    else:
        <take data they sent you and respond appropriately>

If there are no exceptions then we were able to parse the protobuf object and validate the signature.

To access the data from the PaymentRequest just do:

    payment_request = transact.get_verified_payment_request()

And that will return a dictionary with all of the fields of the PaymentRequest and the values that were 
filled in.

## Payment

Please refer to the [BIP70][1] documentation for detailed requirements for a Payment. When it comes to using this 
library to create one you'll need to provide the following:

* transactions: List[bytes]
* refund_to: List[(int, bytes)]  # int: amount, bytes: script (see BIP70 details for more information on scripts)
* merchant_data: Optional[bytes]
* memo: Optional[str]

Create an object for sending like so:

    serialized_payment = transact.create_payment(
        transactions=transactions,
        refund_to=outputs,
        memo=memo,
        merchant_data=merchant_data,
    )

This will provide you with a serialized binary string that you can then send to someone and let them know you gave 
them money.

When you are on the receiving end of one of those binary strings you can do the following to parse one.  
Please note that Payments aren't signed unlike the Invoice/PaymentRequest:

    from transactid.exceptions import DecodeException

    try:
        transact.verify_payment_request(serialized_payment)
    except DecodeException:
        <let sendiner know there was a problem with the porotobuf object they sent over>
    else:
        <take data they sent you and respond appropriately>

If there are no exceptions then we were able to parse the protobuf object.

To access the data from the Payment just do:

    payment_request = transact.get_verified_payment()

And that will return a dictionary with all of the fields of the Payment and the values that were 
filled in.

## PaymentACK

Please refer to the [BIP70][1] documentation for detailed requirements for a PaymentACK. PaymentACKs are a bit different 
than other things in the library.  Due to the fact that art of the PaymentACK is the Payment object you are 
acknowledging, it's not possible to create an ACK without first verifying a Payment.

* memo: Optional[str]

Create an object for sending like so:

    serialized_payment_ack = transact.create_payment_ack(memo=payment_ack_memo)

This will provide you with a serialized binary string that you can then send to someone to acknowledge that they 
sent you money.

When you are on the receiving end of one of those binary strings you can do the following to parse one.  
Please note that Payments aren't signed unlike the Invoice/PaymentRequest:

    from transactid.exceptions import DecodeException

    try:
        transact.verify_payment_ack(serialized_payment_ack)
    except DecodeException:
        <let sendiner know there was a problem with the porotobuf object they sent over>
    else:
        <take data they sent you and respond appropriately>

If there are no exceptions then we were able to parse the protobuf object.

To access the data from the PaymentACK just do:

    payment_request = transact.get_verified_payment_ack()

And that will return a dictionary with all of the fields of the PaymentACK and the values that were 
filled in.


[1]: https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki
[2]: https://github.com/bitcoin/bips/blob/master/bip-0075.mediawiki
