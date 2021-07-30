import unittest

from uaaextras.validators import host_valid_for_domain, email_valid_for_domains

class TestHostValidator(unittest.TestCase):

    def test_host_validator(self):
        assert host_valid_for_domain("example.com", "example.com")
        assert host_valid_for_domain("a.example.com", "example.com")
        assert host_valid_for_domain("a.example.com", "a.example.com")
        assert host_valid_for_domain("b.a.example.com", "a.example.com")
        assert not host_valid_for_domain("aexample.com", "a.example.com")
        assert not host_valid_for_domain("example.com", "a.example.com")
        assert not host_valid_for_domain("aexample.com", "example.com")

    def test_email_validator(self):
        assert email_valid_for_domains("me@example.com", ["example.com", "other.example.com"])
        assert email_valid_for_domains("me@a.example.com", ["example.com", "other.example.com"])
        assert email_valid_for_domains("me@a.example.com", ["a.example.com", "gsa.gov"])
        assert email_valid_for_domains("me@b.a.example.com", ["a.example.com", "gsa.gov"])
        assert not email_valid_for_domains("me@aexample.com", ["a.example.com", "b.example.com"])
        assert not email_valid_for_domains("me@example.com", ["a.example.com", "b.example.com"])
        assert not email_valid_for_domains("me@aexample.com", ["example.com"])
