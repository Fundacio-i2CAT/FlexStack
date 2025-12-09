from unittest.mock import MagicMock, Mock, patch
import unittest
from flexstack.security.security_coder import SecurityCoder
from flexstack.security.certificate import Certificate, OwnCertificate, CertificateIssuer, CertificateVerifier
from flexstack.security.ecdsa_backend import PythonECDSABackend


class TestCertificate(unittest.TestCase):
    def setUp(self) -> None:
        self.coder = SecurityCoder()
        self.backend = PythonECDSABackend()
        self.certificate = Certificate(self.coder, self.backend)

    def test__init__(self):
        self.assertEqual(self.certificate.coder, self.coder)
        self.assertEqual(self.certificate.certificate, None)
        self.assertEqual(self.certificate.issuer, None)
        self.assertEqual(self.certificate.verified, False)

    def test_from_dict(self):
        # Given
        certificate = {'version': 3, 'type': 'explicit', 'issuer': ('self', 'sha256'), 'toBeSigned': {'id': ('name', 'root'), 'cracaId': b'\xa4\x95\x99', 'crlSeries': 0, 'validityPeriod': {'start': 0, 'duration': ('seconds', 30)}, 'certIssuePermissions': [{'subjectPermissions': ('all', None), 'minChainLength': 2, 'chainLengthRange': 0, 'eeType': (b'\x00', 1)}], 'verifyKeyIndicator': ('verificationKey', ('ecdsaNistP256', ('uncompressedP256', {
            'x': b'\xbc\x0b\x0e\xd4\xd1\rRY\xa7\xb9\xff@\x89\xb9\xbc\xf0\x16)\x9b\xed\xa3Ni\x19\x06\xc6\xa3VG\x92\xdd^', 'y': b'\xfd\xd8\xca\x19\xa8xO\xae\xc9\xcd\xcc\xfa2@\x87\x07\x8b\xaf\xb9\x9d\xbdp\xe0\r"E\xd3FEx\xfbj'})))}, 'signature': ('ecdsaNistP256Signature', {'rSig': ('x-only', b"\x89\x03>\x04'\xdd\xd0W\xb5\xf2\xda\x9b\xcbY\x10p\x94\xd1}\xfcD\x15\xb6\xfb\x12\rd\x7f\x9cj\xc4\xb7"), 'sSig': b'8li\n\xa1e\xef\xb8\xa9\n\xb0\x8a\xd4A\x8f\xfb\x10\xb3\x06\x13|_j\x14\xda-\xce\xa9&r\xd9\x9c'})}
        # When
        self.certificate.verify = MagicMock(return_value=True)
        self.certificate.from_dict(certificate)
        # Then
        self.assertEqual(certificate, self.certificate.certificate)
        self.assertIsNot(certificate, self.certificate.certificate)
        self.assertTrue(self.certificate.verified)
        self.assertEqual(
            self.certificate.certificate['toBeSigned']['id'][1], "root")

    def test_decode(self):
        encoded_certificate = b'\x80\x03\x00\x80\xa4\x95\x99\x1bxR\xb8U\x18\x81\ti2cat.net\xa4\x95\x99\x00\x00\x00\x00\x00\x00\x82\x00\x1e\x01\x01\x00\x01\x00\x01\x01 \x81\x00\x80\x80\x81\x80\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x95\x99\x1bxR\xb8U'
        self.certificate.decode(encoded_certificate)
        self.assertEqual(self.certificate.certificate["signature"][1]["sSig"], (
            0xa495991b7852b855).to_bytes(32, byteorder='big'))

    def test_as_hashedid8(self):
        encoded_certificate = b'\x80\x03\x00\x80\xa4\x95\x99\x1bxR\xb8U\x18\x81\ti2cat.net\xa4\x95\x99\x00\x00\x00\x00\x00\x00\x82\x00\x1e\x01\x01\x00\x01\x00\x01\x01 \x81\x00\x80\x80\x81\x80\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x95\x99\x1bxR\xb8U'
        self.certificate.decode(encoded_certificate)
        self.assertEqual(self.certificate.as_hashedid8(),
                         b'\xa9\xdb3\xac\x7fr\xb1\x0b')

    def test_encode(self):
        encoded_certificate = b'\x80\x03\x00\x80\xa4\x95\x99\x1bxR\xb8U\x18\x81\ti2cat.net\xa4\x95\x99\x00\x00\x00\x00\x00\x00\x82\x00\x1e\x01\x01\x00\x01\x00\x01\x01 \x81\x00\x80\x80\x81\x80\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x95\x99\x1bxR\xb8U'
        self.certificate.decode(encoded_certificate)
        self.assertEqual(self.certificate.encode(), encoded_certificate)

    def test_get_list_of_its_aid(self):
        self.certificate.as_clear_certificate()
        self.assertEqual(self.certificate.get_list_of_its_aid(), [0])

    def test_as_clear_certificate(self):
        # Given
        expected_value = {
            "version": 3,
            "type": "explicit",
            "issuer": ("sha256AndDigest", (0xa495991b7852b855).to_bytes(8, byteorder='big')),
            "toBeSigned": {
                "id": ("name", "i2cat.net"),
                "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
                "crlSeries": 0,
                "validityPeriod": {
                    "start": 0,
                    "duration": ("seconds", 30)
                },
                "appPermissions": [{
                    "psid": 0,
                }],
                "certIssuePermissions": [
                    {
                        "subjectPermissions": ("all", None),
                        "minChainLength": 1,
                        "chainLengthRange": 0,
                        "eeType": (b'\x00', 1)
                    }
                ],
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
            },
            "signature": ("ecdsaNistP256Signature", {
                "rSig": ("fill", None),
                "sSig": (0xa495991b7852b855).to_bytes(32, byteorder='big')
            })
        }
        # When
        self.certificate.as_clear_certificate()
        # Then
        self.assertEqual(expected_value, self.certificate.certificate)

    def test_get_issuer_hashedid8(self):
        self.certificate.as_clear_certificate()
        self.assertEqual(self.certificate.get_issuer_hashedid8(
        ), (0xa495991b7852b855).to_bytes(8, byteorder='big'))

    def test_verify(self):
        # Given
        self.certificate.as_clear_certificate()
        self.certificate.verifier = Mock()
        self.certificate.verifier.verify = Mock(return_value=True)
        # When
        self.assertTrue(self.certificate.verify())
        # Then
        self.certificate.verifier.verify.assert_called_once_with(
            self.certificate, None)


class TestOwnCertificate(unittest.TestCase):
    def setUp(self) -> None:
        self.coder = SecurityCoder()
        self.backend = PythonECDSABackend()
        self.own_certificate = OwnCertificate(self.coder, self.backend)

    def test__init__(self):
        self.assertEqual(self.own_certificate.coder, self.coder)
        self.assertIsNotNone(self.own_certificate.certificate)

    def test_initialize_certificate(self):
        # Given
        to_be_signed = {
            "id": ("name", "test.com"),
            "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {
                "start": 0,
                "duration": ("seconds", 30)
            },
            "appPermissions": [{
                "psid": 0,
            }],
            "certIssuePermissions": [
                {
                    "subjectPermissions": ("all", None),
                    "minChainLength": 1,
                    "chainLengthRange": 0,
                    "eeType": (b'\x00', 1)
                }
            ],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        # When
        self.own_certificate.initialize_certificate(to_be_signed)
        # Then
        try:
            self.coder.encode_etsi_ts_103097_certificate(
                self.own_certificate.certificate)
        except Exception:
            self.fail("Certificate is not valid")

    def test_verify_to_be_signed_certificate(self):
        # Given
        acceptable_to_be_signed = {
            "id": ("name", "i2cat.net"),
            "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {
                "start": 0,
                "duration": ("seconds", 30)
            },
            "appPermissions": [{
                "psid": 0,
            }],
            "certIssuePermissions": [
                {
                    "subjectPermissions": ("all", None),
                    "minChainLength": 1,
                    "chainLengthRange": 0,
                    "eeType": (b'\x00', 1)
                }
            ],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        bad_to_be_signed = {
            "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {
                "start": 0,
                "duration": ("seconds", 30)
            },
            "appPermissions": [{
                "psid": 0,
            }],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        # When
        validity_good = self.own_certificate.verify_to_be_signed_certificate(
            acceptable_to_be_signed)
        validity_bad = self.own_certificate.verify_to_be_signed_certificate(
            bad_to_be_signed)
        # Then
        self.assertTrue(validity_good)
        self.assertFalse(validity_bad)

    def test_issue_certificate(self):
        # Given
        certificate_issuer = OwnCertificate(self.coder, self.backend)
        certificate_to_be_issued = OwnCertificate(self.coder, self.backend)
        to_be_signed_to_issue = {
            "id": ("name", "root"),
            "cracaId": (0xa23).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {
                "start": 0,
                "duration": ("seconds", 30)
            },
            # "appPermissions": [{
            #     "psid": 36,
            # },
            #     {
            #     "psid": 38,
            # }],
            "certIssuePermissions": [
                {
                    "subjectPermissions": ("all", None),
                    "minChainLength": 1,
                    "chainLengthRange": 0,
                    "eeType": (b'\x00', 1)
                }
            ],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        certificate_issuer.initialize_certificate(to_be_signed_to_issue, None)
        to_be_signed_to_be_issued = {
            "id": ("name", "issued"),
            "cracaId": (0xa49).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {
                "start": 0,
                "duration": ("seconds", 30)
            },
            "appPermissions": [{
                "psid": 36,
            }],
            # "certIssuePermissions": [
            #     {
            #         "subjectPermissions": ("all", None),
            #         "minChainLength": 1,
            #         "chainLengthRange": 0,
            #         "eeType": (b'\x00', 1)
            #     }
            # ],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        certificate_to_be_issued.initialize_certificate(
            to_be_signed_to_be_issued, certificate_issuer)
        # When
        certificate_issuer.issue_certificate(certificate_to_be_issued)
        # Then
        self.assertTrue(certificate_to_be_issued.verify(
            certificate_to_be_issued.issuer))

    def test_sign_message(self):
        # Given
        message = b"Hello world"
        # When
        signature = self.own_certificate.sign_message(message)
        # Then
        self.assertTrue(self.own_certificate.backend.verify(
            message, signature, self.own_certificate.key_id))


class TestCertificateVerifier(unittest.TestCase):

    def setUp(self) -> None:
        self.coder = MagicMock()
        self.backend = MagicMock()
        self.certificate_verifier = CertificateVerifier(
            self.coder, self.backend)
        self.certificate = Certificate(self.coder, self.backend)
        self.certificate.as_clear_certificate()
        self.issuer = OwnCertificate(self.coder, self.backend)
        self.issuer.as_clear_certificate()

    def test__init__(self):
        # When
        certificate_verifier = CertificateVerifier(self.coder, self.backend)
        # Then
        self.assertIsNotNone(certificate_verifier)
        self.assertIs(certificate_verifier.coder, self.coder)
        self.assertIs(certificate_verifier.backend, self.backend)

    def test_signature_is_nist_p256(self):
        # Given
        self.certificate.certificate['signature'] = ("ecdsaNistP256Signature", {
            "rSig": ("fill", None),
            "sSig": (0xa495991b7852b855).to_bytes(32, byteorder='big')
        })
        # When
        self.assertTrue(
            self.certificate_verifier.signature_is_nist_p256(self.certificate))

    def test_verification_key_is_nist_p256(self):
        self.certificate.certificate['toBeSigned']['verifyKeyIndicator'] = (
            "verificationKey", ("ecdsaNistP256", ("fill", None)))
        self.assertTrue(
            self.certificate_verifier.verification_key_is_nist_p256(self.certificate))

    def test_certificate_is_self_signed(self):
        self.certificate.certificate['issuer'] = ("self", "sha256")
        self.assertTrue(
            self.certificate_verifier.certificate_is_self_signed(self.certificate))

    def test_certificate_is_issued(self):
        self.certificate.certificate['issuer'] = (
            "sha256AndDigest", (0xa495991b7852b855).to_bytes(8, byteorder='big'))
        self.assertTrue(
            self.certificate_verifier.certificate_is_issued(self.certificate))

    def test_check_corresponding_issuer(self):
        self.certificate.certificate['issuer'] = (
            "sha256AndDigest", (0xa495991b7852b855).to_bytes(8, byteorder='big'))
        self.issuer.as_hashedid8 = MagicMock(return_value=(
            0xa495991b7852b855).to_bytes(8, byteorder='big'))
        self.assertTrue(self.certificate_verifier.check_corresponding_issuer(
            self.certificate, self.issuer))

    def test_verify_signature(self):
        self.backend.verify_with_pk = MagicMock(return_value=True)
        self.coder.encode_ToBeSignedCertificate = MagicMock(
            return_value=b'encoded')
        tobesigned_certificate = {"something": "something"}
        signature = {'sign': 'sign'}
        verification_key = {'verificationKey': 'verificationKey'}
        self.assertTrue(self.certificate_verifier.verify_signature(
            tobesigned_certificate, signature, verification_key))
        self.backend.verify_with_pk.assert_called_once_with(
            b'encoded', signature, verification_key)

    def test_verify_self_signed_certificate(self):
        self.certificate_verifier.certificate_is_self_signed = MagicMock(
            return_value=True)
        self.certificate_verifier.signature_is_nist_p256 = MagicMock(
            return_value=True)
        self.certificate_verifier.verification_key_is_nist_p256 = MagicMock(
            return_value=True)
        self.certificate_verifier.verify_signature = MagicMock(
            return_value=True)
        self.assertTrue(
            self.certificate_verifier.verify_self_signed_certificate(self.certificate))
        self.certificate_verifier.certificate_is_self_signed.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.signature_is_nist_p256.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.verification_key_is_nist_p256.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.verify_signature.assert_called_once_with(
            self.certificate.certificate['toBeSigned'], self.certificate.certificate['signature'], self.certificate.certificate['toBeSigned']['verifyKeyIndicator'][1])

    @patch('flexstack.security.certificate.CertificateIssuer')
    def test_verify_correct_issuing_permissions(self, cert_issuer_mock):
        cert_issuer = MagicMock()
        cert_issuer_mock.return_value = cert_issuer
        cert_issuer.check_issuer_has_subject_permissions = MagicMock(
            return_value=True)
        self.assertTrue(self.certificate_verifier.verify_correct_issuing_permissions(
            self.certificate, self.issuer))
        cert_issuer.check_issuer_has_subject_permissions.assert_called_once_with(
            self.certificate, self.issuer)

    def test_verify_issued_certificate(self):
        self.certificate_verifier.certificate_is_issued = MagicMock(
            return_value=True)
        self.certificate_verifier.check_corresponding_issuer = MagicMock(
            return_value=True)
        self.certificate_verifier.signature_is_nist_p256 = MagicMock(
            return_value=True)
        self.certificate_verifier.verification_key_is_nist_p256 = MagicMock(
            return_value=True)
        self.certificate_verifier.verify_signature = MagicMock(
            return_value=True)
        self.assertTrue(self.certificate_verifier.verify_issued_certificate(
            self.certificate, self.issuer))
        self.certificate_verifier.certificate_is_issued.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.check_corresponding_issuer.assert_called_once_with(
            self.certificate, self.issuer)
        self.certificate_verifier.signature_is_nist_p256.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.verification_key_is_nist_p256.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.verify_signature.assert_called_once_with(
            self.certificate.certificate['toBeSigned'], self.certificate.certificate['signature'], self.certificate.certificate['toBeSigned']['verifyKeyIndicator'][1])

    def test_verify(self):
        # When issued
        self.certificate_verifier.certificate_is_issued = MagicMock(
            return_value=True)
        self.certificate_verifier.verify_issued_certificate = MagicMock(
            return_value=True)
        self.assertTrue(self.certificate_verifier.verify(
            self.certificate, self.issuer))
        self.certificate_verifier.certificate_is_issued.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.verify_issued_certificate.assert_called_once_with(
            self.certificate, self.issuer)
        # When self signed
        self.certificate_verifier.certificate_is_issued = MagicMock(
            return_value=False)
        self.certificate_verifier.certificate_is_self_signed = MagicMock(
            return_value=True)
        self.certificate_verifier.verify_self_signed_certificate = MagicMock(
            return_value=True)
        self.assertTrue(self.certificate_verifier.verify(
            self.certificate, self.issuer))
        # self.certificate_verifier.certificate_is_issued.assert_called_once_with(self.certificate)
        self.certificate_verifier.certificate_is_self_signed.assert_called_once_with(
            self.certificate)
        self.certificate_verifier.verify_self_signed_certificate.assert_called_once_with(
            self.certificate)


class TestCertificateIssuer(unittest.TestCase):

    def setUp(self) -> None:
        self.coder = MagicMock()
        self.backend = MagicMock()
        self.certificate_issuer = CertificateIssuer(self.coder, self.backend)
        self.certificate = Certificate(self.coder, self.backend)
        self.certificate.as_clear_certificate()
        self.issuer = OwnCertificate(self.coder, self.backend)
        self.certificate.as_clear_certificate()

    def test__init__(self):
        self.assertEqual(self.certificate_issuer.coder, self.coder)
        self.assertEqual(self.certificate_issuer.backend, self.backend)

    def test_certificate_is_self_signed(self):
        self.assertTrue(self.certificate_issuer.certificate_is_self_signed(
            self.certificate, self.certificate))
        self.assertFalse(self.certificate_issuer.certificate_is_self_signed(
            self.certificate, self.issuer))

    def test_set_issuer_as_self(self):
        self.certificate_issuer.set_issuer_as_self(self.certificate)
        self.assertEqual(
            self.certificate.certificate['issuer'], ("self", "sha256"))

    def test_set_issuer(self):
        self.issuer.as_hashedid8 = MagicMock(
            return_value=b'\xa9\xdb3\xac\x7fr\xb1\x0b')
        self.certificate_issuer.set_issuer(self.certificate, self.issuer)
        self.assertEqual(self.certificate.certificate['issuer'], (
            "sha256AndDigest", b'\xa9\xdb3\xac\x7fr\xb1\x0b'))

    def test_check_enough_min_chain_length_for_issuer(self):
        self.assertTrue(
            self.certificate_issuer.check_enough_min_chain_length_for_issuer(self.issuer))
        self.issuer.certificate['toBeSigned']['certIssuePermissions'][0]['minChainLength'] = 0
        self.assertFalse(
            self.certificate_issuer.check_enough_min_chain_length_for_issuer(self.issuer))

    def test_get_list_of_psid_from_cert_issue_permissions(self):
        self.certificate.certificate['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = ("explicit", [{
            "psid": 36,
        }])
        self.assertEqual(self.certificate_issuer.get_list_of_psid_from_cert_issue_permissions(
            self.certificate), [36])

    def test_get_list_of_psid_from_app_permissions(self):
        self.assertEqual(self.certificate_issuer.get_list_of_psid_from_app_permissions(
            self.certificate), [0])

    def test_get_list_of_needed_permissions(self):
        self.certificate.certificate['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = ("explicit", [{
            "psid": 2,
        }])
        self.assertEqual(self.certificate_issuer.get_list_of_needed_permissions(
            self.certificate), [2, 0])

    def test_get_list_of_allowed_persmissions(self):
        self.certificate.certificate['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = ("explicit", [{
            "psid": 36,
        }])
        self.assertEqual(self.certificate_issuer.get_list_of_allowed_persmissions(
            self.certificate), [36])

    def test_check_all_requested_permissions_are_allowed(self):
        self.assertTrue(self.certificate_issuer.check_all_requested_permissions_are_allowed(
            [2, 3, 4],
            [2, 3, 4, 5]
        ))

    def test_certificate_has_all_permissions(self):
        self.assertTrue(
            self.certificate_issuer.certificate_has_all_permissions(self.certificate))

    def test_check_issuer_has_subject_permissions(self):
        self.issuer.certificate['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = ("explicit", [{
            "psid": 36,
        }])
        self.certificate.certificate['toBeSigned'].pop('certIssuePermissions')
        self.certificate.certificate['toBeSigned']['appPermissions'] = [{
            "psid": 36,
        }]
        self.assertTrue(self.certificate_issuer.check_issuer_has_subject_permissions(
            self.certificate, self.issuer))

    def test_certificate_wants_cert_issue_permissions(self):
        self.assertTrue(
            self.certificate_issuer.certificate_wants_cert_issue_permissions(self.certificate))
        self.certificate.certificate['toBeSigned'].pop('certIssuePermissions')
        self.assertFalse(
            self.certificate_issuer.certificate_wants_cert_issue_permissions(self.certificate))

    def test_set_chain_length_issue_permissions(self):
        # TODO: test
        pass

    def test_sign_certificate(self):
        self.coder.encode_ToBeSignedCertificate = MagicMock(
            return_value=b'\x00\x00\x00\x00')
        self.backend.sign = MagicMock(return_value={'something': 'something'})
        self.certificate_issuer.sign_certificate(self.certificate, self.issuer)
        self.coder.encode_ToBeSignedCertificate.assert_called_once_with(
            self.certificate.certificate['toBeSigned'])
        self.backend.sign.assert_called_once_with(
            b'\x00\x00\x00\x00', self.issuer.key_id)
        self.assertEqual(self.certificate.issuer, self.issuer)
        self.assertEqual(self.certificate.certificate['signature'], {
                         'something': 'something'})

    def test_issue_certificate(self):
        # Self signed case
        self.certificate_issuer.certificate_is_self_signed = MagicMock(
            return_value=True)
        self.certificate_issuer.set_issuer_as_self = MagicMock()
        self.certificate_issuer.sign_certificate = MagicMock()
        self.certificate_issuer.issue_certificate(
            self.issuer, self.issuer)
        self.certificate_issuer.certificate_is_self_signed.assert_called_once_with(
            self.issuer, self.issuer)
        self.certificate_issuer.set_issuer_as_self.assert_called_once_with(
            self.issuer)
        self.certificate_issuer.sign_certificate.assert_called_once_with(
            self.issuer, self.issuer)
        # Not self signed case
        self.certificate_issuer.certificate_is_self_signed = MagicMock(
            return_value=False)
        self.certificate_issuer.check_issuer_has_subject_permissions = MagicMock(
            return_value=True)
        self.certificate_issuer.check_enough_min_chain_length_for_issuer = MagicMock(
            return_value=True)
        self.certificate_issuer.set_chain_length_issue_permissions = MagicMock()
        self.certificate_issuer.set_issuer = MagicMock()
        self.certificate_issuer.sign_certificate = MagicMock()
        self.certificate_issuer.issue_certificate(
            self.certificate, self.issuer)
        self.certificate_issuer.certificate_is_self_signed.assert_called_with(
            self.certificate, self.issuer)
        self.certificate_issuer.check_issuer_has_subject_permissions.assert_called_with(
            self.certificate, self.issuer)
        self.certificate_issuer.check_enough_min_chain_length_for_issuer.assert_called_with(
            self.issuer)
        self.certificate_issuer.set_chain_length_issue_permissions.assert_called_with(
            self.certificate, self.issuer)
        self.certificate_issuer.sign_certificate.assert_called_with(
            self.certificate, self.issuer)
        self.certificate_issuer.set_issuer.assert_called_with(
            self.certificate, self.issuer)


"""
# Brief notes

toBeSigned_root = {
    "id": ("name", "root"),
    "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
    "crlSeries": 0,
    "validityPeriod": {
        "start": 0,
        "duration": ("seconds", 30)
    },
    # "appPermissions": [{
    #     "psid": 36,
    # }],
    "certIssuePermissions": [
        {
            "subjectPermissions": ("all", None),
            "minChainLength": 2,
            "chainLengthRange": 0,
            "eeType": (b'\x00', 1)
        }
    ],
    "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
}
toBeSigned_aa = {
    "id": ("name", "authorization"),
    "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
    "crlSeries": 0,
    "validityPeriod": {
        "start": 0,
        "duration": ("seconds", 30)
    },
    # "appPermissions": [{
    #     "psid": 36,
    # }],
    "certIssuePermissions": [
        {
            "subjectPermissions": ("explicit", [{
                "psid": 36,
            }]),
            "minChainLength": 1,
            "chainLengthRange": 0,
            "eeType": (b'\x00', 1)
        }
    ],
    "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
}
toBeSigned_at = {
    "id": ("name", "authorizationticket"),
    "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
    "crlSeries": 0,
    "validityPeriod": {
        "start": 0,
        "duration": ("seconds", 30)
    },
    "appPermissions": [{
        "psid": 36,
    }],
    "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
}
coder = SecurityCoder()
backend = PythonECDSABackend()
root_certificate = OwnCertificate(coder, backend)
root_certificate.initialize_certificate(toBeSigned_root)
authorization_authority = OwnCertificate(coder, backend)
authorization_authority.initialize_certificate(toBeSigned_aa, root_certificate)
authorization_ticket = OwnCertificate(coder, backend)
authorization_ticket.initialize_certificate(toBeSigned_at, authorization_authority)
authorization_authority.verify(root_certificate)
authorization_ticket.verify(authorization_authority)
print(root_certificate.verified)
print(authorization_authority.verified)
print(authorization_ticket.verified)
with open("Root_CA.coer", "wb") as binary_file:
    binary_file.write(root_certificate.encode())
with open("AuthorizationAuthority.coer", "wb") as binary_file:
    binary_file.write(authorization_authority.encode())
with open("AuthorizationTicket.coer", "wb") as binary_file:
    binary_file.write(authorization_ticket.encode())
"""
