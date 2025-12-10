import unittest
from unittest.mock import MagicMock, patch

from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.certificate import Certificate, OwnCertificate


class TestCertificateLibrary(unittest.TestCase):
    def setUp(self):
        self.backend = MagicMock()
        self.root_cert = MagicMock(spec=Certificate)
        self.root_cert.verify.return_value = True
        self.root_cert.as_hashedid8.return_value = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.root_cert.certificate = {
            "issuer": ("self", "sha256")
        }

        self.aa_cert = MagicMock(spec=Certificate)
        self.aa_cert.verify.return_value = True
        self.aa_cert.as_hashedid8.return_value = b'\x11\x12\x13\x14\x15\x16\x17\x18'
        self.aa_cert.certificate = {
            "issuer": ("sha256AndDigest", b'\x01\x02\x03\x04\x05\x06\x07\x08')
        }

        self.at_cert = MagicMock(spec=Certificate)
        self.at_cert.verify.return_value = True
        self.at_cert.as_hashedid8.return_value = b'\x21\x22\x23\x24\x25\x26\x27\x28'
        self.at_cert.certificate = {
            "issuer": ("sha256AndDigest", b'\x11\x12\x13\x14\x15\x16\x17\x18')
        }

    def test_init_empty(self):
        """Test initialization with empty certificate lists"""
        library = CertificateLibrary(self.backend, [], [], [])
        self.assertEqual(library.own_certificates, {})
        self.assertEqual(library.known_authorization_tickets, {})
        self.assertEqual(library.known_authorization_authorities, {})
        self.assertEqual(library.known_root_certificates, {})

    def test_init_with_root_certificate(self):
        """Test initialization with root certificates"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])
        self.assertIn(b'\x01\x02\x03\x04\x05\x06\x07\x08', library.known_root_certificates)

    def test_init_with_aa_certificate(self):
        """Test initialization with AA certificates"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])
        self.assertIn(b'\x01\x02\x03\x04\x05\x06\x07\x08', library.known_root_certificates)
        self.assertIn(b'\x11\x12\x13\x14\x15\x16\x17\x18', library.known_authorization_authorities)

    def test_init_with_at_certificate(self):
        """Test initialization with AT certificates"""
        library = CertificateLibrary(
            self.backend, [self.root_cert], [self.aa_cert], [self.at_cert]
        )
        self.assertIn(b'\x01\x02\x03\x04\x05\x06\x07\x08', library.known_root_certificates)
        self.assertIn(b'\x11\x12\x13\x14\x15\x16\x17\x18', library.known_authorization_authorities)
        self.assertIn(b'\x21\x22\x23\x24\x25\x26\x27\x28', library.known_authorization_tickets)

    def test_add_root_certificate_valid(self):
        """Test adding a valid root certificate"""
        library = CertificateLibrary(self.backend, [], [], [])
        library.add_root_certificate(self.root_cert)
        self.assertIn(b'\x01\x02\x03\x04\x05\x06\x07\x08', library.known_root_certificates)

    def test_add_root_certificate_invalid(self):
        """Test adding an invalid root certificate"""
        library = CertificateLibrary(self.backend, [], [], [])
        self.root_cert.verify.return_value = False
        library.add_root_certificate(self.root_cert)
        self.assertNotIn(b'\x01\x02\x03\x04\x05\x06\x07\x08', library.known_root_certificates)

    def test_add_authorization_authority_valid(self):
        """Test adding a valid AA certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])
        library.add_authorization_authority(self.aa_cert)
        self.assertIn(b'\x11\x12\x13\x14\x15\x16\x17\x18', library.known_authorization_authorities)

    def test_add_authorization_authority_no_issuer(self):
        """Test adding an AA certificate without a known issuer"""
        library = CertificateLibrary(self.backend, [], [], [])
        library.add_authorization_authority(self.aa_cert)
        self.assertNotIn(b'\x11\x12\x13\x14\x15\x16\x17\x18', library.known_authorization_authorities)

    def test_add_authorization_authority_invalid(self):
        """Test adding an invalid AA certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])
        self.aa_cert.verify.return_value = False
        library.add_authorization_authority(self.aa_cert)
        self.assertNotIn(b'\x11\x12\x13\x14\x15\x16\x17\x18', library.known_authorization_authorities)

    def test_add_authorization_ticket_valid(self):
        """Test adding a valid AT certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])
        library.add_authorization_ticket(self.at_cert)
        self.assertIn(b'\x21\x22\x23\x24\x25\x26\x27\x28', library.known_authorization_tickets)

    def test_add_authorization_ticket_no_issuer(self):
        """Test adding an AT certificate without a known issuer"""
        library = CertificateLibrary(self.backend, [], [], [])
        library.add_authorization_ticket(self.at_cert)
        self.assertNotIn(b'\x21\x22\x23\x24\x25\x26\x27\x28', library.known_authorization_tickets)

    def test_add_authorization_ticket_invalid(self):
        """Test adding an invalid AT certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])
        self.at_cert.verify.return_value = False
        library.add_authorization_ticket(self.at_cert)
        self.assertNotIn(b'\x21\x22\x23\x24\x25\x26\x27\x28', library.known_authorization_tickets)

    def test_add_authorization_ticket_duplicate(self):
        """Test adding a duplicate AT certificate"""
        library = CertificateLibrary(
            self.backend, [self.root_cert], [self.aa_cert], [self.at_cert]
        )
        # Reset mock to check if verify is called again
        self.at_cert.verify.reset_mock()
        library.add_authorization_ticket(self.at_cert)
        # Should not call verify again since it's already in the library
        self.at_cert.verify.assert_not_called()

    def test_add_own_certificate_valid(self):
        """Test adding a valid own certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])
        own_cert = MagicMock(spec=OwnCertificate)
        own_cert.verify.return_value = True
        own_cert.as_hashedid8.return_value = b'\x31\x32\x33\x34\x35\x36\x37\x38'
        own_cert.certificate = {
            "issuer": ("sha256AndDigest", b'\x11\x12\x13\x14\x15\x16\x17\x18')
        }
        library.add_own_certificate(own_cert)
        self.assertIn(b'\x31\x32\x33\x34\x35\x36\x37\x38', library.own_certificates)

    def test_add_own_certificate_no_issuer(self):
        """Test adding an own certificate without a known issuer"""
        library = CertificateLibrary(self.backend, [], [], [])
        own_cert = MagicMock(spec=OwnCertificate)
        own_cert.verify.return_value = True
        own_cert.as_hashedid8.return_value = b'\x31\x32\x33\x34\x35\x36\x37\x38'
        own_cert.certificate = {
            "issuer": ("sha256AndDigest", b'\x11\x12\x13\x14\x15\x16\x17\x18')
        }
        library.add_own_certificate(own_cert)
        self.assertNotIn(b'\x31\x32\x33\x34\x35\x36\x37\x38', library.own_certificates)

    def test_get_issuer_certificate_self_signed(self):
        """Test getting issuer for a self-signed certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])
        result = library.get_issuer_certificate(self.root_cert)
        self.assertIsNone(result)

    def test_get_issuer_certificate_from_root(self):
        """Test getting issuer from root certificates"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])
        result = library.get_issuer_certificate(self.aa_cert)
        self.assertEqual(result, self.root_cert)

    def test_get_issuer_certificate_from_aa(self):
        """Test getting issuer from AA certificates"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])
        result = library.get_issuer_certificate(self.at_cert)
        self.assertEqual(result, self.aa_cert)

    def test_get_issuer_certificate_not_found(self):
        """Test getting issuer when not found"""
        library = CertificateLibrary(self.backend, [], [], [])
        result = library.get_issuer_certificate(self.aa_cert)
        self.assertIsNone(result)

    def test_get_issuer_certificate_unknown_type(self):
        """Test getting issuer with unknown issuer type"""
        library = CertificateLibrary(self.backend, [], [], [])
        unknown_cert = MagicMock(spec=Certificate)
        unknown_cert.certificate = {
            "issuer": ("unknown", b'\x00\x00\x00\x00\x00\x00\x00\x00')
        }
        with self.assertRaises(ValueError):
            library.get_issuer_certificate(unknown_cert)

    def test_get_authorization_ticket_by_hashedid8_found(self):
        """Test getting AT by hashedid8 when found"""
        library = CertificateLibrary(
            self.backend, [self.root_cert], [self.aa_cert], [self.at_cert]
        )
        result = library.get_authorization_ticket_by_hashedid8(b'\x21\x22\x23\x24\x25\x26\x27\x28')
        self.assertEqual(result, self.at_cert)

    def test_get_authorization_ticket_by_hashedid8_not_found(self):
        """Test getting AT by hashedid8 when not found"""
        library = CertificateLibrary(self.backend, [], [], [])
        result = library.get_authorization_ticket_by_hashedid8(b'\x21\x22\x23\x24\x25\x26\x27\x28')
        self.assertIsNone(result)

    @patch.object(Certificate, 'from_dict')
    def test_verify_sequence_of_certificates_empty(self, mock_from_dict):
        """Test verifying an empty sequence of certificates"""
        library = CertificateLibrary(self.backend, [], [], [])
        result = library.verify_sequence_of_certificates([], self.backend)
        self.assertIsNone(result)

    @patch.object(Certificate, 'from_dict')
    def test_verify_sequence_of_certificates_single_known(self, mock_from_dict):
        """Test verifying a single certificate that is already known"""
        library = CertificateLibrary(
            self.backend, [self.root_cert], [self.aa_cert], [self.at_cert]
        )
        mock_cert = MagicMock(spec=Certificate)
        mock_cert.as_hashedid8.return_value = b'\x21\x22\x23\x24\x25\x26\x27\x28'
        mock_from_dict.return_value = mock_cert

        result = library.verify_sequence_of_certificates([{"cert": "data"}], self.backend)
        self.assertEqual(result, self.at_cert)

    @patch.object(Certificate, 'from_dict')
    def test_verify_sequence_of_certificates_single_unknown_valid(self, mock_from_dict):
        """Test verifying a single unknown but valid certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])

        mock_cert = MagicMock(spec=Certificate)
        mock_cert.as_hashedid8.return_value = b'\x41\x42\x43\x44\x45\x46\x47\x48'
        mock_cert.verify.return_value = True
        mock_cert.certificate = {
            "issuer": ("sha256AndDigest", b'\x11\x12\x13\x14\x15\x16\x17\x18')
        }
        mock_from_dict.return_value = mock_cert

        result = library.verify_sequence_of_certificates([{"cert": "data"}], self.backend)
        self.assertEqual(result, mock_cert)

    @patch.object(Certificate, 'from_dict')
    def test_verify_sequence_of_certificates_single_unknown_invalid(self, mock_from_dict):
        """Test verifying a single unknown and invalid certificate"""
        library = CertificateLibrary(self.backend, [self.root_cert], [self.aa_cert], [])

        mock_cert = MagicMock(spec=Certificate)
        mock_cert.as_hashedid8.return_value = b'\x41\x42\x43\x44\x45\x46\x47\x48'
        mock_cert.verify.return_value = False
        mock_cert.certificate = {
            "issuer": ("sha256AndDigest", b'\x11\x12\x13\x14\x15\x16\x17\x18')
        }
        mock_from_dict.return_value = mock_cert

        result = library.verify_sequence_of_certificates([{"cert": "data"}], self.backend)
        self.assertIsNone(result)

    @patch.object(Certificate, 'from_dict')
    def test_verify_sequence_of_certificates_two_valid(self, mock_from_dict):
        """Test verifying a sequence of two valid certificates"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])

        mock_aa = MagicMock(spec=Certificate)
        mock_aa.as_hashedid8.return_value = b'\x51\x52\x53\x54\x55\x56\x57\x58'
        mock_aa.get_issuer_hashedid8.return_value = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        mock_aa.verify.return_value = True
        mock_aa.certificate = {
            "issuer": ("sha256AndDigest", b'\x01\x02\x03\x04\x05\x06\x07\x08')
        }

        mock_at = MagicMock(spec=Certificate)
        mock_at.as_hashedid8.return_value = b'\x61\x62\x63\x64\x65\x66\x67\x68'
        mock_at.verify.return_value = True
        mock_at.certificate = {
            "issuer": ("sha256AndDigest", b'\x51\x52\x53\x54\x55\x56\x57\x58')
        }

        mock_from_dict.side_effect = [mock_aa, mock_aa, mock_at]

        result = library.verify_sequence_of_certificates(
            [{"at": "data"}, {"aa": "data"}], self.backend
        )
        self.assertEqual(result, mock_at)

    @patch.object(Certificate, 'from_dict')
    def test_verify_sequence_of_certificates_three_with_known_root(self, mock_from_dict):
        """Test verifying a sequence of three certificates with known root"""
        library = CertificateLibrary(self.backend, [self.root_cert], [], [])

        mock_root = MagicMock(spec=Certificate)
        mock_root.as_hashedid8.return_value = b'\x01\x02\x03\x04\x05\x06\x07\x08'

        mock_from_dict.return_value = mock_root

        with patch.object(library, 'verify_sequence_of_certificates', wraps=library.verify_sequence_of_certificates) as mock_verify:
            # This will call recursively with certificates[:-1]
            result = library.verify_sequence_of_certificates(
                [{"at": "data"}, {"aa": "data"}, {"root": "data"}], self.backend
            )


if __name__ == '__main__':
    unittest.main()
