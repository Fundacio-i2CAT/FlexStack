from flexstack.security.sn_sap import (
    SNDECAPConfirm,
    SNDECAPReport,
    SNDECAPRequest,
    SNENCAPConfirm,
    SNENCAPRequest,
    SNLOGSECURITYEVENTConfirm,
    SNLOGSECURITYEVENTRequest,
    SNLOGSECURITYEVENTEventEvidenceType,
    SNLOGSECURITYEVENTEventType,
    SNIDUNLOCKConfirm,
    SNIDUNLOCKRequest,
    SNIDLOCKConfirm,
    SNIDLOCKRequest,
    SNIDCHANGETRIGGERConfirm,
    SNIDCHANGETRIGGERRequest,
    SNIDCHANGEUNSUBSCRIBEConfirm,
    SNIDCHANGEUNSUBSCRIBERequest,
    SNIDCHANGESUBSCRIBEConfirm,
    SNIDCHANGESUBSCRIBERequest,
    SNIDCHANGEEVENTResponse,
    SNIDCHANGEEVENTIndication,
    SNIDCHANGEEVENTCommand,
    SNDECRYPTConfirm,
    ReportDecrypt,
    SNDECRYPTRequest,
    SNENCRYPTConfirm,
    SNENCRYPTRequest,
    SNVERIFYConfirm,
    ReportVerify,
    SNVERIFYRequest,
    SNSIGNConfirm,
    SNSIGNRequest,
)

import unittest


class TestSNSIGNRequest(unittest.TestCase):

    def setUp(self):
        # Set up some sample data for testing
        self.tbs_message_length = 16
        self.tbs_message = b"sample_message"
        self.its_aid = 12345
        self.permissions_length = 10
        self.permissions = b"permissions_data"
        self.context_information = b"context_info"
        self.key_handle = 67890

    def test_initialization_required_fields(self):
        # Test initialization with required fields only
        request = SNSIGNRequest(
            tbs_message_length=self.tbs_message_length,
            tbs_message=self.tbs_message,
            its_aid=self.its_aid,
            permissions_length=self.permissions_length,
            permissions=self.permissions,
        )
        self.assertEqual(request.tbs_message_length, self.tbs_message_length)
        self.assertEqual(request.tbs_message, self.tbs_message)
        self.assertEqual(request.its_aid, self.its_aid)
        self.assertEqual(request.permissions_length, self.permissions_length)
        self.assertEqual(request.permissions, self.permissions)
        self.assertIsNone(request.context_information)
        self.assertIsNone(request.key_handle)

    def test_initialization_all_fields(self):
        # Test initialization with all fields
        request = SNSIGNRequest(
            tbs_message_length=self.tbs_message_length,
            tbs_message=self.tbs_message,
            its_aid=self.its_aid,
            permissions_length=self.permissions_length,
            permissions=self.permissions,
            context_information=self.context_information,
            key_handle=self.key_handle,
        )
        self.assertEqual(request.tbs_message_length, self.tbs_message_length)
        self.assertEqual(request.tbs_message, self.tbs_message)
        self.assertEqual(request.its_aid, self.its_aid)
        self.assertEqual(request.permissions_length, self.permissions_length)
        self.assertEqual(request.permissions, self.permissions)
        self.assertEqual(request.context_information, self.context_information)
        self.assertEqual(request.key_handle, self.key_handle)

    def test_repr(self):
        # Test the __repr__ method
        request = SNSIGNRequest(
            tbs_message_length=self.tbs_message_length,
            tbs_message=self.tbs_message,
            its_aid=self.its_aid,
            permissions_length=self.permissions_length,
            permissions=self.permissions,
            context_information=self.context_information,
            key_handle=self.key_handle,
        )
        expected_repr = f"SNSIGNRequest(tbs_message_length={self.tbs_message_length}, tbs_message={self.tbs_message}, its_aid={self.its_aid}, permissions_length={self.permissions_length}, permissions={self.permissions}, context_information={self.context_information}, key_handle={self.key_handle})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        # Test the __str__ method
        request = SNSIGNRequest(
            tbs_message_length=self.tbs_message_length,
            tbs_message=self.tbs_message,
            its_aid=self.its_aid,
            permissions_length=self.permissions_length,
            permissions=self.permissions,
            context_information=self.context_information,
            key_handle=self.key_handle,
        )
        expected_str = f"SNSIGNRequest(tbs_message_length={self.tbs_message_length}, tbs_message={self.tbs_message}, its_aid={self.its_aid}, permissions_length={self.permissions_length}, permissions={self.permissions}, context_information={self.context_information}, key_handle={self.key_handle})"
        self.assertEqual(str(request), expected_str)


class TestSNSIGNConfirm(unittest.TestCase):

    def setUp(self):
        # Set up some sample data for testing
        self.sec_message_length = 20
        self.sec_message = b"signed_message"

    def test_initialization(self):
        # Test initialization with required fields
        confirm = SNSIGNConfirm(
            sec_message_length=self.sec_message_length, sec_message=self.sec_message
        )
        self.assertEqual(confirm.sec_message_length, self.sec_message_length)
        self.assertEqual(confirm.sec_message, self.sec_message)

    def test_repr(self):
        # Test the __repr__ method
        confirm = SNSIGNConfirm(
            sec_message_length=self.sec_message_length, sec_message=self.sec_message
        )
        expected_repr = f"SNSIGNConfirm(sec_message_length={self.sec_message_length}, sec_message={self.sec_message})"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        # Test the __str__ method
        confirm = SNSIGNConfirm(
            sec_message_length=self.sec_message_length, sec_message=self.sec_message
        )
        expected_str = f"SNSIGNConfirm(sec_message_length={self.sec_message_length}, sec_message={self.sec_message})"
        self.assertEqual(str(confirm), expected_str)


class TestSNVERIFYRequest(unittest.TestCase):

    def setUp(self):
        # Set up some sample data for testing
        self.sec_header_length = 10
        self.sec_header = b"sec_header"
        self.message_length = 30
        self.message = b"message_to_be_verified"

    def test_initialization(self):
        # Test initialization with required fields
        request = SNVERIFYRequest(
            sec_header_length=self.sec_header_length,
            sec_header=self.sec_header,
            message_length=self.message_length,
            message=self.message,
        )
        self.assertEqual(request.sec_header_length, self.sec_header_length)
        self.assertEqual(request.sec_header, self.sec_header)
        self.assertEqual(request.message_length, self.message_length)
        self.assertEqual(request.message, self.message)

    def test_repr(self):
        # Test the __repr__ method
        request = SNVERIFYRequest(
            sec_header_length=self.sec_header_length,
            sec_header=self.sec_header,
            message_length=self.message_length,
            message=self.message,
        )
        expected_repr = f"SNVERIFYRequest(sec_header_length={self.sec_header_length}, sec_header={self.sec_header}, message_length={self.message_length}, message={self.message})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        # Test the __str__ method
        request = SNVERIFYRequest(
            sec_header_length=self.sec_header_length,
            sec_header=self.sec_header,
            message_length=self.message_length,
            message=self.message,
        )
        expected_str = f"SNVERIFYRequest(sec_header_length={self.sec_header_length}, sec_header={self.sec_header}, message_length={self.message_length}, message={self.message})"
        self.assertEqual(str(request), expected_str)


class TestReportVerify(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(ReportVerify.SUCCESS.value, 0)
        self.assertEqual(ReportVerify.FALSE_SIGNATURE.value, 1)
        self.assertEqual(ReportVerify.INVALID_CERTIFICATE.value, 2)
        self.assertEqual(ReportVerify.REVOKED_CERTIFICATE.value, 3)
        self.assertEqual(ReportVerify.INCONSISTENT_CHAIN.value, 4)
        self.assertEqual(ReportVerify.INVALID_TIMESTAMP.value, 5)
        self.assertEqual(ReportVerify.DUPLICATE_MESSAGE.value, 6)
        self.assertEqual(ReportVerify.INVALID_MOBILITY_DATA.value, 7)
        self.assertEqual(ReportVerify.UNSIGNED_MESSAGE.value, 8)
        self.assertEqual(ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND.value, 9)
        self.assertEqual(ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE.value, 10)
        self.assertEqual(ReportVerify.INCOMPATIBLE_PROTOCOL.value, 11)


class TestSNVERIFYConfirm(unittest.TestCase):

    def setUp(self):
        self.report = ReportVerify.SUCCESS
        self.certificate_id = b"certificate"
        self.its_aid_length = 16
        self.its_aid = b"its_aid"
        self.permissions = b"permissions"

    def test_initialization(self):
        confirm = SNVERIFYConfirm(
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        self.assertEqual(confirm.report, self.report)
        self.assertEqual(confirm.certificate_id, self.certificate_id)
        self.assertEqual(confirm.its_aid_length, self.its_aid_length)
        self.assertEqual(confirm.its_aid, self.its_aid)
        self.assertEqual(confirm.permissions, self.permissions)

    def test_repr(self):
        confirm = SNVERIFYConfirm(
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        expected_repr = f"SNVERIFYConfirm(report={self.report}, certificate_id={self.certificate_id}, its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, permissions={self.permissions}, plain_message={b''})"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNVERIFYConfirm(
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        expected_str = f"SNVERIFYConfirm(report={self.report}, certificate_id={self.certificate_id}, its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, permissions={self.permissions}, plain_message={b''})"
        self.assertEqual(str(confirm), expected_str)

    def test_plain_message_defaults_to_empty(self):
        """Test that plain_message defaults to empty bytes when not provided."""
        confirm = SNVERIFYConfirm(
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        self.assertEqual(confirm.plain_message, b"")

    def test_plain_message_can_be_set(self):
        """Test that plain_message is stored correctly when explicitly provided."""
        payload = b"inner_gn_payload"
        confirm = SNVERIFYConfirm(
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
            plain_message=payload,
        )
        self.assertEqual(confirm.plain_message, payload)


class TestSNENCRYPTRequest(unittest.TestCase):

    def setUp(self):
        self.tbe_payload_length = 64
        self.tbe_payload = b"payload"
        self.target_id_list_length = 2
        self.target_id_list = [b"id1", b"id2"]
        self.context_information = b"context"

    def test_initialization(self):
        request = SNENCRYPTRequest(
            tbe_payload_length=self.tbe_payload_length,
            tbe_payload=self.tbe_payload,
            target_id_list_length=self.target_id_list_length,
            target_id_list=self.target_id_list,
            context_information=self.context_information,
        )
        self.assertEqual(request.tbe_payload_length, self.tbe_payload_length)
        self.assertEqual(request.tbe_payload, self.tbe_payload)
        self.assertEqual(request.target_id_list_length, self.target_id_list_length)
        self.assertEqual(request.target_id_list, self.target_id_list)
        self.assertEqual(request.context_information, self.context_information)

    def test_repr(self):
        request = SNENCRYPTRequest(
            tbe_payload_length=self.tbe_payload_length,
            tbe_payload=self.tbe_payload,
            target_id_list_length=self.target_id_list_length,
            target_id_list=self.target_id_list,
            context_information=self.context_information,
        )
        expected_repr = f"SNENCRYPTRequest(tbe_payload_length={self.tbe_payload_length}, tbe_payload={self.tbe_payload}, target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list}, context_information={self.context_information})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNENCRYPTRequest(
            tbe_payload_length=self.tbe_payload_length,
            tbe_payload=self.tbe_payload,
            target_id_list_length=self.target_id_list_length,
            target_id_list=self.target_id_list,
            context_information=self.context_information,
        )
        expected_str = f"SNENCRYPTRequest(tbe_payload_length={self.tbe_payload_length}, tbe_payload={self.tbe_payload}, target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list}, context_information={self.context_information})"
        self.assertEqual(str(request), expected_str)


class TestSNENCRYPTConfirm(unittest.TestCase):

    def setUp(self):
        self.encrypted_message_length = 128
        self.encrypted_message = b"encrypted_message"

    def test_initialization(self):
        confirm = SNENCRYPTConfirm(
            encrypted_message_length=self.encrypted_message_length,
            encrypted_message=self.encrypted_message,
        )
        self.assertEqual(
            confirm.encrypted_message_length, self.encrypted_message_length
        )
        self.assertEqual(confirm.encrypted_message, self.encrypted_message)

    def test_repr(self):
        confirm = SNENCRYPTConfirm(
            encrypted_message_length=self.encrypted_message_length,
            encrypted_message=self.encrypted_message,
        )
        expected_repr = f"SNENCRYPTConfirm(encrypted_message_length={self.encrypted_message_length}, encrypted_message={self.encrypted_message})"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNENCRYPTConfirm(
            encrypted_message_length=self.encrypted_message_length,
            encrypted_message=self.encrypted_message,
        )
        expected_str = f"SNENCRYPTConfirm(encrypted_message_length={self.encrypted_message_length}, encrypted_message={self.encrypted_message})"
        self.assertEqual(str(confirm), expected_str)


class TestSNDECRYPTRequest(unittest.TestCase):

    def setUp(self):
        self.encrypted_message_length = 64
        self.encrypted_message = b"encrypted_message"

    def test_initialization(self):
        request = SNDECRYPTRequest(
            encrypted_message_length=self.encrypted_message_length,
            encrypted_message=self.encrypted_message,
        )
        self.assertEqual(
            request.encrypted_message_length, self.encrypted_message_length
        )
        self.assertEqual(request.encrypted_message, self.encrypted_message)

    def test_repr(self):
        request = SNDECRYPTRequest(
            encrypted_message_length=self.encrypted_message_length,
            encrypted_message=self.encrypted_message,
        )
        expected_repr = f"SNDECRYPTRequest(encrypted_message_length={self.encrypted_message_length}, encrypted_message={self.encrypted_message})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNDECRYPTRequest(
            encrypted_message_length=self.encrypted_message_length,
            encrypted_message=self.encrypted_message,
        )
        expected_str = f"SNDECRYPTRequest(encrypted_message_length={self.encrypted_message_length}, encrypted_message={self.encrypted_message})"
        self.assertEqual(str(request), expected_str)


class TestReportDecrypt(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(ReportDecrypt.SUCCESS.value, 0)
        self.assertEqual(ReportDecrypt.UNENCRYPTED_MESSAGE.value, 1)
        self.assertEqual(ReportDecrypt.DECRYPTION_ERROR.value, 2)
        self.assertEqual(ReportDecrypt.INCOMPATIBLE_PROTOCOL.value, 3)


class TestSNDECRYPTConfirm(unittest.TestCase):

    def setUp(self):
        self.plaintext_message_length = 128
        self.plaintext_message = b"plaintext_message"
        self.report = ReportDecrypt.SUCCESS

    def test_initialization(self):
        confirm = SNDECRYPTConfirm(
            plaintext_message_length=self.plaintext_message_length,
            plaintext_message=self.plaintext_message,
            report=self.report,
        )
        self.assertEqual(
            confirm.plaintext_message_length, self.plaintext_message_length
        )
        self.assertEqual(confirm.plaintext_message, self.plaintext_message)
        self.assertEqual(confirm.report, self.report)

    def test_repr(self):
        confirm = SNDECRYPTConfirm(
            plaintext_message_length=self.plaintext_message_length,
            plaintext_message=self.plaintext_message,
            report=self.report,
        )
        expected_repr = f"SNDECRYPTConfirm(plaintext_message_length={self.plaintext_message_length}, plaintext_message={self.plaintext_message}, report={self.report})"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNDECRYPTConfirm(
            plaintext_message_length=self.plaintext_message_length,
            plaintext_message=self.plaintext_message,
            report=self.report,
        )
        expected_str = f"SNDECRYPTConfirm(plaintext_message_length={self.plaintext_message_length}, plaintext_message={self.plaintext_message}, report={self.report})"
        self.assertEqual(str(confirm), expected_str)


class TestSNIDCHANGEEVENTCommand(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(SNIDCHANGEEVENTCommand.PREPARE.value, 0)
        self.assertEqual(SNIDCHANGEEVENTCommand.COMMIT.value, 1)
        self.assertEqual(SNIDCHANGEEVENTCommand.ABORT.value, 2)
        self.assertEqual(SNIDCHANGEEVENTCommand.DEREG.value, 3)


class TestSNIDCHANGEEVENTIndication(unittest.TestCase):

    def setUp(self):
        self.command = SNIDCHANGEEVENTCommand.PREPARE
        self.identifier = b"identifier"
        self.subscriber_data = b"subscriber_data"

    def test_initialization(self):
        indication = SNIDCHANGEEVENTIndication(
            command=self.command,
            identifier=self.identifier,
            subscriber_data=self.subscriber_data,
        )
        self.assertEqual(indication.command, self.command)
        self.assertEqual(indication.identifier, self.identifier)
        self.assertEqual(indication.subscriber_data, self.subscriber_data)

    def test_initialization_without_subscriber_data(self):
        indication = SNIDCHANGEEVENTIndication(
            command=self.command, identifier=self.identifier
        )
        self.assertEqual(indication.command, self.command)
        self.assertEqual(indication.identifier, self.identifier)
        self.assertIsNone(indication.subscriber_data)

    def test_repr(self):
        indication = SNIDCHANGEEVENTIndication(
            command=self.command,
            identifier=self.identifier,
            subscriber_data=self.subscriber_data,
        )
        expected_repr = f"SNIDCHANGEEVENTIndication(command={self.command}, identifier={self.identifier}, subscriber_data={self.subscriber_data})"
        self.assertEqual(repr(indication), expected_repr)

    def test_str(self):
        indication = SNIDCHANGEEVENTIndication(
            command=self.command,
            identifier=self.identifier,
            subscriber_data=self.subscriber_data,
        )
        expected_str = f"SNIDCHANGEEVENTIndication(command={self.command}, id={self.identifier}, subscriber_data={self.subscriber_data})"
        self.assertEqual(str(indication), expected_str)


class TestSNIDCHANGEEVENTResponse(unittest.TestCase):

    def test_initialization(self):
        response = SNIDCHANGEEVENTResponse(return_code=True)
        self.assertTrue(response.return_code)

    def test_repr(self):
        response = SNIDCHANGEEVENTResponse(return_code=True)
        expected_repr = f"SNIDCHANGEEVENTResponse(return_code={response.return_code})"
        self.assertEqual(repr(response), expected_repr)

    def test_str(self):
        response = SNIDCHANGEEVENTResponse(return_code=True)
        expected_str = f"SNIDCHANGEEVENTResponse(return_code={response.return_code})"
        self.assertEqual(str(response), expected_str)


class TestSNIDCHANGESUBSCRIBERequest(unittest.TestCase):

    def setUp(self):
        self.idchange_event_hook = lambda indication, data: None
        self.subscriber_data = b"subscriber_data"

    def test_initialization(self):
        request = SNIDCHANGESUBSCRIBERequest(
            idchange_event_hook=self.idchange_event_hook,
            subscriber_data=self.subscriber_data,
        )
        self.assertEqual(request.idchange_event_hook, self.idchange_event_hook)
        self.assertEqual(request.subscriber_data, self.subscriber_data)

    def test_initialization_without_subscriber_data(self):
        request = SNIDCHANGESUBSCRIBERequest(
            idchange_event_hook=self.idchange_event_hook
        )
        self.assertEqual(request.idchange_event_hook, self.idchange_event_hook)
        self.assertIsNone(request.subscriber_data)

    def test_repr(self):
        request = SNIDCHANGESUBSCRIBERequest(
            idchange_event_hook=self.idchange_event_hook,
            subscriber_data=self.subscriber_data,
        )
        expected_repr = f"SNIDCHANGESUBSCRIBERequest(idchange_event_hook={self.idchange_event_hook}, subscriber_data={self.subscriber_data})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNIDCHANGESUBSCRIBERequest(
            idchange_event_hook=self.idchange_event_hook,
            subscriber_data=self.subscriber_data,
        )
        expected_str = f"SNIDCHANGESUBSCRIBERequest(idchange_event_hook={self.idchange_event_hook}, subscriber_data={self.subscriber_data})"
        self.assertEqual(str(request), expected_str)


class TestSNIDCHANGESUBSCRIBEConfirm(unittest.TestCase):

    def test_initialization(self):
        confirm = SNIDCHANGESUBSCRIBEConfirm(subscription=123456789)
        self.assertEqual(confirm.subscription, 123456789)

    def test_repr(self):
        confirm = SNIDCHANGESUBSCRIBEConfirm(subscription=123456789)
        expected_repr = (
            f"SNIDCHANGESUBSCRIBEConfirm(subscription={confirm.subscription})"
        )
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNIDCHANGESUBSCRIBEConfirm(subscription=123456789)
        expected_str = (
            f"SNIDCHANGESUBSCRIBEConfirm(subscription={confirm.subscription})"
        )
        self.assertEqual(str(confirm), expected_str)


class TestSNIDCHANGEUNSUBSCRIBERequest(unittest.TestCase):

    def test_initialization(self):
        request = SNIDCHANGEUNSUBSCRIBERequest(subscription=123456789)
        self.assertEqual(request.subscription, 123456789)

    def test_repr(self):
        request = SNIDCHANGEUNSUBSCRIBERequest(subscription=123456789)
        expected_repr = (
            f"SNIDCHANGEUNSUBSCRIBERequest(subscription={request.subscription})"
        )
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNIDCHANGEUNSUBSCRIBERequest(subscription=123456789)
        expected_str = (
            f"SNIDCHANGEUNSUBSCRIBERequest(subscription={request.subscription})"
        )
        self.assertEqual(str(request), expected_str)


class TestSNIDCHANGEUNSUBSCRIBEConfirm(unittest.TestCase):

    def test_repr(self):
        confirm = SNIDCHANGEUNSUBSCRIBEConfirm()
        expected_repr = "SNIDCHANGEUNSUBSCRIBEConfirm()"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNIDCHANGEUNSUBSCRIBEConfirm()
        expected_str = "SNIDCHANGEUNSUBSCRIBEConfirm()"
        self.assertEqual(str(confirm), expected_str)


class TestSNIDCHANGETRIGGERRequest(unittest.TestCase):

    def test_repr(self):
        request = SNIDCHANGETRIGGERRequest()
        expected_repr = "SNIDCHANGETRIGGERRequest()"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNIDCHANGETRIGGERRequest()
        expected_str = "SNIDCHANGETRIGGERRequest()"
        self.assertEqual(str(request), expected_str)


class TestSNIDCHANGETRIGGERConfirm(unittest.TestCase):

    def test_repr(self):
        confirm = SNIDCHANGETRIGGERConfirm()
        expected_repr = "SNIDCHANGETRIGGERConfirm()"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNIDCHANGETRIGGERConfirm()
        expected_str = "SNIDCHANGETRIGGERConfirm()"
        self.assertEqual(str(confirm), expected_str)


class TestSNIDLOCKRequest(unittest.TestCase):

    def test_initialization(self):
        request = SNIDLOCKRequest(duration=60)
        self.assertEqual(request.duration, 60)

    def test_repr(self):
        request = SNIDLOCKRequest(duration=60)
        expected_repr = f"SNIDLOCKRequest(duration={request.duration})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNIDLOCKRequest(duration=60)
        expected_str = f"SNIDLOCKRequest(duration={request.duration})"
        self.assertEqual(str(request), expected_str)


class TestSNIDLOCKConfirm(unittest.TestCase):

    def test_initialization(self):
        confirm = SNIDLOCKConfirm(lock_handle=123456789)
        self.assertEqual(confirm.lock_handle, 123456789)

    def test_repr(self):
        confirm = SNIDLOCKConfirm(lock_handle=123456789)
        expected_repr = f"SNIDLOCKConfirm(lock_handle={confirm.lock_handle})"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNIDLOCKConfirm(lock_handle=123456789)
        expected_str = f"SNIDLOCKConfirm(lock_handle={confirm.lock_handle})"
        self.assertEqual(str(confirm), expected_str)


class TestSNIDUNLOCKRequest(unittest.TestCase):

    def test_initialization(self):
        request = SNIDUNLOCKRequest(lock_handle=123456789)
        self.assertEqual(request.lock_handle, 123456789)

    def test_repr(self):
        request = SNIDUNLOCKRequest(lock_handle=123456789)
        expected_repr = f"SNIDUNLOCKRequest(lock_handle={request.lock_handle})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNIDUNLOCKRequest(lock_handle=123456789)
        expected_str = f"SNIDUNLOCKRequest(lock_handle={request.lock_handle})"
        self.assertEqual(str(request), expected_str)


class TestSNIDUNLOCKConfirm(unittest.TestCase):

    def test_repr(self):
        confirm = SNIDUNLOCKConfirm()
        expected_repr = "SNIDUNLOCKConfirm()"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNIDUNLOCKConfirm()
        expected_str = "SNIDUNLOCKConfirm()"
        self.assertEqual(str(confirm), expected_str)


class TestSNLOGSECURITYEVENTEventType(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.TIME_CONSISTENCY_FAILED.value, 0x01
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.LOCATION_CONSISTENCY_FAILED.value, 0x02
        )
        self.assertEqual(SNLOGSECURITYEVENTEventType.ID_CONSISTENCY_FAILED.value, 0x03)
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.DISALLOWED_MESSAGE_CONTENT.value, 0x04
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.DISALLOWED_MESSAGE_FREQUENCY.value, 0x05
        )
        self.assertEqual(SNLOGSECURITYEVENTEventType.REPLAY_DETECTION_TIME.value, 0x06)
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.REPLAY_DETECTION_LOCATION.value, 0x07
        )
        self.assertEqual(SNLOGSECURITYEVENTEventType.MOVEMENT_PLAUSIBILITY.value, 0x08)
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.APPEARANCE_PLAUSIBILITY.value, 0x09
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.LOCATION_PLAUSIBILITY_SENSOR.value, 0x0A
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.LOCATION_PLAUSIBILITY_MAP.value, 0x0B
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.LOCATION_PLAUSIBILITY_CONTRADICTION.value, 0x0C
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.LOCATION_PLAUSIBILITY_CONTRADICTION_VEHICLE_DIMENSION.value,
            0x0D,
        )
        self.assertEqual(
            SNLOGSECURITYEVENTEventType.LOCATION_PLAUSIBILITY_CONTRADICTION_NEIGHBOR_INFO.value,
            0x0E,
        )


class TestSNLOGSECURITYEVENTEventEvidenceType(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(SNLOGSECURITYEVENTEventEvidenceType.CAM.value, 0x01)
        self.assertEqual(SNLOGSECURITYEVENTEventEvidenceType.DENM.value, 0x02)


class TestSNLOGSECURITYEVENTRequest(unittest.TestCase):

    def setUp(self):
        self.event_type = SNLOGSECURITYEVENTEventType.TIME_CONSISTENCY_FAILED
        self.neighbour_id_list_length = 2
        self.neighbour_id_list = [b"id1", b"id2"]
        self.event_time = 1627587800
        self.event_location = {"latitude": 52.5200, "longitude": 13.4050}
        self.event_evidence_list_length = 1
        self.event_evidence_list = [{"length": 10, "data": b"evidence"}]
        self.event_evidence_type = SNLOGSECURITYEVENTEventEvidenceType.CAM
        self.event_evidence_content_length = 100
        self.event_evidence_content = b"evidence_content"

    def test_initialization(self):
        request = SNLOGSECURITYEVENTRequest(
            event_type=self.event_type,
            neighbour_id_list_length=self.neighbour_id_list_length,
            neighbour_id_list=self.neighbour_id_list,
            event_time=self.event_time,
            event_location=self.event_location,
            event_evidence_list_length=self.event_evidence_list_length,
            event_evidence_list=self.event_evidence_list,
            event_evidence_type=self.event_evidence_type,
            event_evidence_content_length=self.event_evidence_content_length,
            event_evidence_content=self.event_evidence_content,
        )
        self.assertEqual(request.event_type, self.event_type)
        self.assertEqual(
            request.neighbour_id_list_length, self.neighbour_id_list_length
        )
        self.assertEqual(request.neighbour_id_list, self.neighbour_id_list)
        self.assertEqual(request.event_time, self.event_time)
        self.assertEqual(request.event_location, self.event_location)
        self.assertEqual(
            request.event_evidence_list_length, self.event_evidence_list_length
        )
        self.assertEqual(request.event_evidence_list, self.event_evidence_list)
        self.assertEqual(request.event_evidence_type, self.event_evidence_type)
        self.assertEqual(
            request.event_evidence_content_length, self.event_evidence_content_length
        )
        self.assertEqual(request.event_evidence_content, self.event_evidence_content)

    def test_repr(self):
        request = SNLOGSECURITYEVENTRequest(
            event_type=self.event_type,
            neighbour_id_list_length=self.neighbour_id_list_length,
            neighbour_id_list=self.neighbour_id_list,
            event_time=self.event_time,
            event_location=self.event_location,
            event_evidence_list_length=self.event_evidence_list_length,
            event_evidence_list=self.event_evidence_list,
            event_evidence_type=self.event_evidence_type,
            event_evidence_content_length=self.event_evidence_content_length,
            event_evidence_content=self.event_evidence_content,
        )
        expected_repr = (
            f"SNLOGSECURITYEVENTRequest(event_type={self.event_type}, "
            f"neighbour_id_list_length={self.neighbour_id_list_length}, "
            f"neighbour_id_list={self.neighbour_id_list}, event_time={self.event_time}, "
            f"event_location={self.event_location}, event_evidence_list_length={self.event_evidence_list_length}, "
            f"event_evidence_list={self.event_evidence_list}, event_evidence_type={self.event_evidence_type}, "
            f"event_evidence_content_length={self.event_evidence_content_length}, "
            f"event_evidence_content={self.event_evidence_content})"
        )
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNLOGSECURITYEVENTRequest(
            event_type=self.event_type,
            neighbour_id_list_length=self.neighbour_id_list_length,
            neighbour_id_list=self.neighbour_id_list,
            event_time=self.event_time,
            event_location=self.event_location,
            event_evidence_list_length=self.event_evidence_list_length,
            event_evidence_list=self.event_evidence_list,
            event_evidence_type=self.event_evidence_type,
            event_evidence_content_length=self.event_evidence_content_length,
            event_evidence_content=self.event_evidence_content,
        )
        expected_str = (
            f"SNLOGSECURITYEVENTRequest(event_type={self.event_type}, "
            f"neighbour_id_list_length={self.neighbour_id_list_length}, "
            f"neighbour_id_list={self.neighbour_id_list}, event_time={self.event_time}, "
            f"event_location={self.event_location}, event_evidence_list_length={self.event_evidence_list_length}, "
            f"event_evidence_list={self.event_evidence_list}, event_evidence_type={self.event_evidence_type}, "
            f"event_evidence_content_length={self.event_evidence_content_length}, "
            f"event_evidence_content={self.event_evidence_content})"
        )
        self.assertEqual(str(request), expected_str)


class TestSNLOGSECURITYEVENTConfirm(unittest.TestCase):

    def test_repr(self):
        confirm = SNLOGSECURITYEVENTConfirm()
        expected_repr = "SNLOGSECURITYEVENTConfirm()"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNLOGSECURITYEVENTConfirm()
        expected_str = "SNLOGSECURITYEVENTConfirm()"
        self.assertEqual(str(confirm), expected_str)


class TestSNENCAPRequest(unittest.TestCase):

    def setUp(self):
        self.tbe_packet_length = 64
        self.tbe_packet = b"tbe_packet"
        self.sec_services = 1
        self.its_aid_length = 16
        self.its_aid = 100
        self.permissions = b"permissions"
        self.context_information = b"context_info"
        self.target_id_list_length = 2
        self.target_id_list = [b"id1", b"id2"]

    def test_initialization(self):
        request = SNENCAPRequest(
            tbe_packet_length=self.tbe_packet_length,
            tbe_packet=self.tbe_packet,
            sec_services=self.sec_services,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
            context_information=self.context_information,
            target_id_list_length=self.target_id_list_length,
            target_id_list=self.target_id_list,
        )
        self.assertEqual(request.tbe_packet_length, self.tbe_packet_length)
        self.assertEqual(request.tbe_packet, self.tbe_packet)
        self.assertEqual(request.sec_services, self.sec_services)
        self.assertEqual(request.its_aid_length, self.its_aid_length)
        self.assertEqual(request.its_aid, self.its_aid)
        self.assertEqual(request.permissions, self.permissions)
        self.assertEqual(request.context_information, self.context_information)
        self.assertEqual(request.target_id_list_length, self.target_id_list_length)
        self.assertEqual(request.target_id_list, self.target_id_list)

    def test_repr(self):
        request = SNENCAPRequest(
            tbe_packet_length=self.tbe_packet_length,
            tbe_packet=self.tbe_packet,
            sec_services=self.sec_services,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
            context_information=self.context_information,
            target_id_list_length=self.target_id_list_length,
            target_id_list=self.target_id_list,
        )
        expected_repr = (
            f"SNENCAPRequest(tbe_packet_length={self.tbe_packet_length}, "
            f"tbe_packet={self.tbe_packet}, sec_services={self.sec_services}, "
            f"its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, "
            f"permissions={self.permissions}, context_information={self.context_information}, "
            f"target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list})"
        )
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNENCAPRequest(
            tbe_packet_length=self.tbe_packet_length,
            tbe_packet=self.tbe_packet,
            sec_services=self.sec_services,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
            context_information=self.context_information,
            target_id_list_length=self.target_id_list_length,
            target_id_list=self.target_id_list,
        )
        expected_str = (
            f"SNENCAPRequest(tbe_packet_length={self.tbe_packet_length}, "
            f"tbe_packet={self.tbe_packet}, sec_services={self.sec_services}, "
            f"its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, "
            f"permissions={self.permissions}, context_information={self.context_information}, "
            f"target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list})"
        )
        self.assertEqual(str(request), expected_str)


class TestSNENCAPConfirm(unittest.TestCase):

    def setUp(self):
        self.sec_packet_length = 128
        self.sec_packet = b"security_packet"

    def test_initialization(self):
        confirm = SNENCAPConfirm(
            sec_packet_length=self.sec_packet_length, sec_packet=self.sec_packet
        )
        self.assertEqual(confirm.sec_packet_length, self.sec_packet_length)
        self.assertEqual(confirm.sec_packet, self.sec_packet)

    def test_repr(self):
        confirm = SNENCAPConfirm(
            sec_packet_length=self.sec_packet_length, sec_packet=self.sec_packet
        )
        expected_repr = f"SNENCAPConfirm(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNENCAPConfirm(
            sec_packet_length=self.sec_packet_length, sec_packet=self.sec_packet
        )
        expected_str = f"SNENCAPConfirm(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"
        self.assertEqual(str(confirm), expected_str)


class TestSNDECAPRequest(unittest.TestCase):

    def setUp(self):
        self.sec_packet_length = 128
        self.sec_packet = b"security_packet"

    def test_initialization(self):
        request = SNDECAPRequest(
            sec_packet_length=self.sec_packet_length, sec_packet=self.sec_packet
        )
        self.assertEqual(request.sec_packet_length, self.sec_packet_length)
        self.assertEqual(request.sec_packet, self.sec_packet)

    def test_repr(self):
        request = SNDECAPRequest(
            sec_packet_length=self.sec_packet_length, sec_packet=self.sec_packet
        )
        expected_repr = f"SNDECAPRequest(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"
        self.assertEqual(repr(request), expected_repr)

    def test_str(self):
        request = SNDECAPRequest(
            sec_packet_length=self.sec_packet_length, sec_packet=self.sec_packet
        )
        expected_str = f"SNDECAPRequest(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"
        self.assertEqual(str(request), expected_str)


class TestSNDECAPReport(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(SNDECAPReport.SUCCESS.value, 0)
        self.assertEqual(SNDECAPReport.FALSE_SIGNATURE.value, 1)
        self.assertEqual(SNDECAPReport.INVALID_CERTIFICATE.value, 2)
        self.assertEqual(SNDECAPReport.REVOKED_CERTIFICATE.value, 3)
        self.assertEqual(SNDECAPReport.INCONSISTENT_CHAIN.value, 4)
        self.assertEqual(SNDECAPReport.INVALID_TIMESTAMP.value, 5)
        self.assertEqual(SNDECAPReport.DUPLICATE_MESSAGE.value, 6)
        self.assertEqual(SNDECAPReport.INVALID_MOBILITY_DATA.value, 7)
        self.assertEqual(SNDECAPReport.UNSIGNED_MESSAGE.value, 8)
        self.assertEqual(SNDECAPReport.SIGNER_CERTIFICATE_NOT_FOUND.value, 9)
        self.assertEqual(SNDECAPReport.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE.value, 10)
        self.assertEqual(SNDECAPReport.INCOMPATIBLE_PROTOCOL.value, 11)
        self.assertEqual(SNDECAPReport.UNENCRYPTED_MESSAGE.value, 12)
        self.assertEqual(SNDECAPReport.DECRYPTION_ERROR.value, 13)


class TestSNDECAPConfirm(unittest.TestCase):

    def setUp(self):
        self.plaintext_packet_length = 128
        self.plaintext_packet = b"plaintext_packet"
        self.report = SNDECAPReport.SUCCESS
        self.certificate_id = b"cert_id"
        self.its_aid_length = 16
        self.its_aid = 100
        self.permissions = b"permissions"

    def test_initialization(self):
        confirm = SNDECAPConfirm(
            plaintext_packet_length=self.plaintext_packet_length,
            plaintext_packet=self.plaintext_packet,
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        self.assertEqual(confirm.plaintext_packet_length, self.plaintext_packet_length)
        self.assertEqual(confirm.plaintext_packet, self.plaintext_packet)
        self.assertEqual(confirm.report, self.report)
        self.assertEqual(confirm.certificate_id, self.certificate_id)
        self.assertEqual(confirm.its_aid_length, self.its_aid_length)
        self.assertEqual(confirm.its_aid, self.its_aid)
        self.assertEqual(confirm.permissions, self.permissions)

    def test_initialization_without_optional_fields(self):
        confirm = SNDECAPConfirm(
            plaintext_packet_length=self.plaintext_packet_length,
            plaintext_packet=self.plaintext_packet,
            report=self.report,
        )
        self.assertEqual(confirm.plaintext_packet_length, self.plaintext_packet_length)
        self.assertEqual(confirm.plaintext_packet, self.plaintext_packet)
        self.assertEqual(confirm.report, self.report)
        self.assertIsNone(confirm.certificate_id)
        self.assertIsNone(confirm.its_aid_length)
        self.assertIsNone(confirm.its_aid)
        self.assertIsNone(confirm.permissions)

    def test_repr(self):
        confirm = SNDECAPConfirm(
            plaintext_packet_length=self.plaintext_packet_length,
            plaintext_packet=self.plaintext_packet,
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        expected_repr = (
            f"SNDECAPConfirm(plaintext_packet_length={self.plaintext_packet_length}, "
            f"plaintext_packet={self.plaintext_packet}, report={self.report}, "
            f"certificate_id={self.certificate_id}, its_aid_length={self.its_aid_length}, "
            f"its_aid={self.its_aid}, permissions={self.permissions})"
        )
        self.assertEqual(repr(confirm), expected_repr)

    def test_str(self):
        confirm = SNDECAPConfirm(
            plaintext_packet_length=self.plaintext_packet_length,
            plaintext_packet=self.plaintext_packet,
            report=self.report,
            certificate_id=self.certificate_id,
            its_aid_length=self.its_aid_length,
            its_aid=self.its_aid,
            permissions=self.permissions,
        )
        expected_str = (
            f"SNDECAPConfirm(plaintext_packet_length={self.plaintext_packet_length}, "
            f"plaintext_packet={self.plaintext_packet}, report={self.report}, "
            f"certificate_id={self.certificate_id}, its_aid_length={self.its_aid_length}, "
            f"its_aid={self.its_aid}, permissions={self.permissions})"
        )
        self.assertEqual(str(confirm), expected_str)
