import smtplib
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError   # noqa: F401


class InvalidDomainError(ValueError):
    pass


class Emailer(object):
    def __init__(self, smtp_from, smtp_host, smtp_port=25, smtp_user=None, smtp_pass=None,
                 smtp_debug=1, valid_domains=None):

        self.smtp_from = smtp_from
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.smtp_debug = smtp_debug

        self._valid_domains = valid_domains

    def validate_email(self, email, valid_domains_only=False):
        email = email.strip().rstrip()
        if not email:
            raise ValueError('Email cannot be blank.')

        validated = validate_email(email)

        if self._valid_domains is not None and valid_domains_only:
            if not validated['domain'].endswith(tuple(self._valid_domains)):
                raise InvalidDomainError("{0} is not in the list of valid domains".format(validated['domain']))

        return validated['email']

    def send_email(self, email, subject, body):
        """Send an email via an external SMTP server

        Args:
            email(str): The recepient of the message
            subject(str): The subject of the email
            body(str): The HTML body of the email

        Raises:
            socket.error: Could not connect to the SMTP Server

        Returns:
            True: The mail was accepted for delivery.

        """

        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['To'] = email
        msg['From'] = self.smtp_from

        s = smtplib.SMTP(self.smtp_host, self.smtp_port)
        s.set_debuglevel(self.smtp_debug)

        if self.smtp_user is not None and self.smtp_pass is not None:
            s.login(self.smtp_user, self.smtp_pass)

        s.sendmail(self.smtp_from, [email], msg.as_string())
        s.quit()

        return True
