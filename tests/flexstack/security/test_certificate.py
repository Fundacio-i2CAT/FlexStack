from unittest.mock import MagicMock, patch
import unittest
from flexstack.security.security_coder import SecurityCoder
from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend


class TestCertificate(unittest.TestCase):
    def setUp(self) -> None:
        self.coder = SecurityCoder()
        self.backend = PythonECDSABackend()

    def test__init__(self):
        certificate = Certificate()
        self.assertEqual(certificate.certificate, {})
        self.assertEqual(certificate.issuer, None)

    def test_from_dict(self):
        # Given
        certificate_dict = {'version': 3, 'type': 'explicit', 'issuer': ('self', 'sha256'), 'toBeSigned': {'id': ('name', 'root'), 'cracaId': b'\xa4\x95\x99', 'crlSeries': 0, 'validityPeriod': {'start': 0, 'duration': ('seconds', 30)}, 'certIssuePermissions': [{'subjectPermissions': ('all', None), 'minChainLength': 2, 'chainLengthRange': 0, 'eeType': (b'\x00', 1)}], 'verifyKeyIndicator': ('verificationKey', ('ecdsaNistP256', ('uncompressedP256', {
            'x': b'\xbc\x0b\x0e\xd4\xd1\rRY\xa7\xb9\xff@\x89\xb9\xbc\xf0\x16)\x9b\xed\xa3Ni\x19\x06\xc6\xa3VG\x92\xdd^', 'y': b'\xfd\xd8\xca\x19\xa8xO\xae\xc9\xcd\xcc\xfa2@\x87\x07\x8b\xaf\xb9\x9d\xbdp\xe0\r"E\xd3FEx\xfbj'})))}, 'signature': ('ecdsaNistP256Signature', {'rSig': ('x-only', b"\x89\x03>\x04'\xdd\xd0W\xb5\xf2\xda\x9b\xcbY\x10p\x94\xd1}\xfcD\x15\xb6\xfb\x12\rd\x7f\x9cj\xc4\xb7"), 'sSig': b'8li\n\xa1e\xef\xb8\xa9\n\xb0\x8a\xd4A\x8f\xfb\x10\xb3\x06\x13|_j\x14\xda-\xce\xa9&r\xd9\x9c'})}
        # When
        cert = Certificate.from_dict(certificate_dict)
        # Then
        self.assertEqual(certificate_dict, cert.certificate)
        self.assertIsNot(certificate_dict, cert.certificate)
        self.assertEqual(cert.certificate['toBeSigned']['id'][1], "root")

    def test_decode(self):
        encoded_certificate = b'\x80\x03\x00\x80\xa4\x95\x99\x1bxR\xb8U\x18\x81\ti2cat.net\xa4\x95\x99\x00\x00\x00\x00\x00\x00\x82\x00\x1e\x01\x01\x00\x01\x00\x01\x01 \x81\x00\x80\x80\x81\x80\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x95\x99\x1bxR\xb8U'
        cert = Certificate().decode(encoded_certificate)
        self.assertEqual(cert.certificate["signature"][1]["sSig"], (
            0xa495991b7852b855).to_bytes(32, byteorder='big'))

    def test_as_hashedid8(self):
        encoded_certificate = b'\x80\x03\x00\x80\xa4\x95\x99\x1bxR\xb8U\x18\x81\ti2cat.net\xa4\x95\x99\x00\x00\x00\x00\x00\x00\x82\x00\x1e\x01\x01\x00\x01\x00\x01\x01 \x81\x00\x80\x80\x81\x80\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x95\x99\x1bxR\xb8U'
        cert = Certificate().decode(encoded_certificate)
        self.assertEqual(cert.as_hashedid8(),
                         b'\xa9\xdb3\xac\x7fr\xb1\x0b')

    def test_encode(self):
        encoded_certificate = b'\x80\x03\x00\x80\xa4\x95\x99\x1bxR\xb8U\x18\x81\ti2cat.net\xa4\x95\x99\x00\x00\x00\x00\x00\x00\x82\x00\x1e\x01\x01\x00\x01\x00\x01\x01 \x81\x00\x80\x80\x81\x80\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x95\x99\x1bxR\xb8U'
        cert = Certificate().decode(encoded_certificate)
        self.assertEqual(cert.encode(), encoded_certificate)

    def test_get_list_of_its_aid(self):
        cert = Certificate.as_clear_certificate()
        self.assertEqual(cert.get_list_of_its_aid(), (0,))

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
        cert = Certificate.as_clear_certificate()
        # Then
        self.assertEqual(expected_value, cert.certificate)

    def test_get_issuer_hashedid8(self):
        cert = Certificate.as_clear_certificate()
        self.assertEqual(cert.get_issuer_hashedid8(
        ), (0xa495991b7852b855).to_bytes(8, byteorder='big'))

    def test_signature_is_nist_p256(self):
        cert = Certificate.as_clear_certificate()
        self.assertTrue(cert.signature_is_nist_p256())

    def test_verification_key_is_nist_p256(self):
        cert = Certificate.as_clear_certificate()
        self.assertTrue(cert.verification_key_is_nist_p256())

    def test_certificate_is_self_signed(self):
        cert_dict = Certificate.as_clear_certificate().certificate.copy()
        cert_dict['issuer'] = ("self", "sha256")
        cert = Certificate.from_dict(cert_dict)
        self.assertTrue(cert.certificate_is_self_signed())

    def test_certificate_is_issued(self):
        cert = Certificate.as_clear_certificate()
        self.assertTrue(cert.certificate_is_issued())

    def test_check_corresponding_issuer(self):
        cert = Certificate.as_clear_certificate()
        issuer = MagicMock()
        issuer.as_hashedid8 = MagicMock(return_value=(
            0xa495991b7852b855).to_bytes(8, byteorder='big'))
        self.assertTrue(cert.check_corresponding_issuer(issuer))

    def test_certificate_wants_cert_issue_permissions(self):
        cert = Certificate.as_clear_certificate()
        self.assertTrue(cert.certificate_wants_cert_issue_permissions())

    def test_get_list_of_psid_from_cert_issue_permissions(self):
        cert_dict = Certificate.as_clear_certificate().certificate.copy()
        cert_dict['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = (
            "explicit", [{"psid": 36}])
        cert = Certificate.from_dict(cert_dict)
        self.assertEqual(
            cert.get_list_of_psid_from_cert_issue_permissions(), [36])

    def test_get_list_of_psid_from_app_permissions(self):
        cert = Certificate.as_clear_certificate()
        self.assertEqual(cert.get_list_of_psid_from_app_permissions(), [0])

    def test_get_list_of_needed_permissions(self):
        cert_dict = Certificate.as_clear_certificate().certificate.copy()
        cert_dict['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = (
            "explicit", [{"psid": 2}])
        cert = Certificate.from_dict(cert_dict)
        self.assertEqual(cert.get_list_of_needed_permissions(), [2, 0])

    def test_get_list_of_allowed_persmissions(self):
        cert_dict = Certificate.as_clear_certificate().certificate.copy()
        cert_dict['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = (
            "explicit", [{"psid": 36}])
        cert = Certificate.from_dict(cert_dict)
        self.assertEqual(cert.get_list_of_allowed_persmissions(), [36])

    def test_certificate_has_all_permissions(self):
        cert = Certificate.as_clear_certificate()
        self.assertTrue(cert.certificate_has_all_permissions())

    def test_check_all_requested_permissions_are_allowed(self):
        self.assertTrue(Certificate.check_all_requested_permissions_are_allowed(
            [2, 3, 4],
            [2, 3, 4, 5]
        ))

    def test_check_issuer_has_subject_permissions(self):
        cert_dict = Certificate.as_clear_certificate().certificate.copy()
        cert_dict['toBeSigned'].pop('certIssuePermissions')
        cert_dict['toBeSigned']['appPermissions'] = [{"psid": 36}]
        cert = Certificate.from_dict(cert_dict)

        issuer_dict = Certificate.as_clear_certificate().certificate.copy()
        issuer_dict['toBeSigned']['certIssuePermissions'][0]['subjectPermissions'] = (
            "explicit", [{"psid": 36}])
        issuer = Certificate.from_dict(issuer_dict)

        self.assertTrue(cert.check_issuer_has_subject_permissions(issuer))

    def test_verify_signature(self):
        backend = MagicMock()
        backend.verify_with_pk = MagicMock(return_value=True)
        tobesigned_certificate = {"something": "something"}
        signature = {'sign': 'sign'}
        verification_key = {'verificationKey': 'verificationKey'}
        with patch('flexstack.security.certificate.SECURITY_CODER') as mock_coder:
            mock_coder.encode_ToBeSignedCertificate = MagicMock(
                return_value=b'encoded')
            self.assertTrue(Certificate.verify_signature(
                backend, tobesigned_certificate, signature, verification_key))
            backend.verify_with_pk.assert_called_once_with(
                b'encoded', signature, verification_key)

    def test_set_issuer_as_self(self):
        cert = Certificate.as_clear_certificate()
        new_cert = cert.set_issuer_as_self()
        self.assertEqual(new_cert.certificate['issuer'], ("self", "sha256"))

    def test_set_issuer(self):
        cert = Certificate.as_clear_certificate()
        issuer = MagicMock()
        issuer.as_hashedid8 = MagicMock(
            return_value=b'\xa9\xdb3\xac\x7fr\xb1\x0b')
        new_cert = cert.set_issuer(issuer)
        self.assertEqual(
            new_cert.certificate['issuer'], ("sha256AndDigest", b'\xa9\xdb3\xac\x7fr\xb1\x0b'))

    def test_verify(self):
        # Test self-signed verification
        backend = self.backend
        to_be_signed = {
            "id": ("name", "root"),
            "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {"start": 0, "duration": ("seconds", 30)},
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
        root_certificate = OwnCertificate.initialize_certificate(
            backend, to_be_signed)
        self.assertTrue(root_certificate.verify(backend))


class TestOwnCertificate(unittest.TestCase):
    def setUp(self) -> None:
        self.coder = SecurityCoder()
        self.backend = PythonECDSABackend()

    def test__init__(self):
        own_cert = OwnCertificate()
        self.assertEqual(own_cert.certificate, {})
        self.assertEqual(own_cert.key_id, 0)

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
        own_certificate = OwnCertificate.initialize_certificate(
            self.backend, to_be_signed)
        # Then
        try:
            self.coder.encode_etsi_ts_103097_certificate(
                own_certificate.certificate)
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
        validity_good = OwnCertificate.verify_to_be_signed_certificate(
            acceptable_to_be_signed)
        validity_bad = OwnCertificate.verify_to_be_signed_certificate(
            bad_to_be_signed)
        # Then
        self.assertTrue(validity_good)
        self.assertFalse(validity_bad)

    def test_issue_certificate(self):
        # Given
        to_be_signed_to_issue = {
            "id": ("name", "root"),
            "cracaId": (0xa23).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {
                "start": 0,
                "duration": ("seconds", 30)
            },
            "certIssuePermissions": [
                {
                    "subjectPermissions": ("all", None),
                    "minChainLength": 3,
                    "chainLengthRange": 0,
                    "eeType": (b'\x00', 1)
                }
            ],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        certificate_issuer = OwnCertificate.initialize_certificate(
            self.backend, to_be_signed_to_issue)

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
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))
        }
        certificate_to_be_issued = OwnCertificate.initialize_certificate(
            backend=self.backend, to_be_signed_certificate=to_be_signed_to_be_issued, issuer=certificate_issuer)
        # Then
        self.assertTrue(certificate_to_be_issued.verify(self.backend))

    def test_sign_message(self):
        # Given
        to_be_signed = {
            "id": ("name", "test"),
            "cracaId": (0xa49599).to_bytes(3, byteorder='big'),
            "crlSeries": 0,
            "validityPeriod": {"start": 0, "duration": ("seconds", 30)},
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
        own_certificate = OwnCertificate.initialize_certificate(
            self.backend, to_be_signed)
        message = b"Hello world"
        # When
        signature = own_certificate.sign_message(self.backend, message)
        # Then
        self.assertTrue(self.backend.verify(
            message, signature, own_certificate.key_id))
