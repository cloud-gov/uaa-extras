import unittest

from mock import patch

from uaaextras.email import Emailer, InvalidDomainError, EmailNotValidError


@patch('uaaextras.email.smtplib')
class TestEmailer(unittest.TestCase):

    def setUp(self):
        self.emailer = Emailer('bar@example.com', 'remote-host', 9160)

    def test_send_email_no_auth(self, smtplib):
        """Email is sent as expected"""

        self.emailer.send_email('foo@example.com', 'da subject', 'body content')

        smtplib.SMTP.assert_called_with('remote-host', 9160)
        args = smtplib.SMTP().sendmail.call_args
        self.assertEqual(args[0][:2], ('bar@example.com', ['foo@example.com']))
        self.assertIn('body content', args[0][2])
        self.assertIn('To: foo@example.com', args[0][2])
        self.assertIn('Subject: da subject', args[0][2])

    def test_send_email_auth(self, smtplib):
        """IF SMTP_USER and SMTP_PASS are provided, smtp.login() is called"""

        authemailer = Emailer('bar@example.com', 'remote-host', 9160, 'user', 'pass')
        authemailer.send_email('foo@example.com', 'da subject', 'body content')

        smtplib.SMTP.assert_called_with('remote-host', 9160)
        smtplib.SMTP().login.assert_called_with('user', 'pass')

    def test_blank_email(self, smtplib):
        """ValueError is raised when a blank email is provided"""

        with self.assertRaises(ValueError):
            self.emailer.validate_email('')

    def test_invalid_email(self, smtplib):
        """EmailNotValidError is raised when emails are not syntactically valid"""

        with self.assertRaises(EmailNotValidError):
            self.emailer.validate_email('this-is-not@.legit')

    def test_valid_domains_only_noop(self, smtplib):
        """When valid domains isn't set, valid_domains_only has not effect"""

        self.assertEqual('test@example.com', self.emailer.validate_email('test@example.com', valid_domains_only=True))

    def test_valid_domains(self, smtplib):
        """When valid domains is set, it's honored"""

        validemailer = Emailer('bar@example.com', 'remote-host', 9160, valid_domains=['example.org'])

        with self.assertRaises(InvalidDomainError):
            validemailer.validate_email('test@example.com', valid_domains_only=True)

        # we get our email address back because it's valid
        self.assertEqual('test@example.org', self.emailer.validate_email('test@example.org', valid_domains_only=True))

        # we get it back because we said ignore
        self.assertEqual('test@example.com', self.emailer.validate_email('test@example.com', valid_domains_only=False))

    def test_normalize_email(self, smtplib):
        """Validation normalizes domain names"""

        self.assertEqual('tEst@example.org', self.emailer.validate_email('tEst@ExAmplE.Org'))
