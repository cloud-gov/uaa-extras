import json
from posixpath import join as urljoin
import unittest

from mock import Mock, patch
from requests.auth import HTTPBasicAuth

from uaaextras.clients import UAAError, UAAClient
from uaaextras.tests.webapp import TEST_TOKEN


class TestUAAClient(unittest.TestCase):
    """Test our UAA Client"""

    def setUp(self):
        self.requests = Mock()
        self.requests_patch = patch('uaaextras.clients.uaa.requests', self.requests)
        self.requests_patch.start()

        self.token = Mock(return_value='a-client-token')
        self.token_patch = patch('uaaextras.clients.uaa.UAAClient._get_client_token', self.token)
        self.token_patch.start()

        self.uaac = UAAClient('http://example.com', 'client id', 'client secret', True)

    def tearDown(self):
        self.requests_patch.stop()
        try:
            self.token_patch.stop()
        except RuntimeError:
            pass

    def test_error_message(self):
        """Error messages are populated properly in the exception"""
        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        u = UAAError(r)

        self.assertEqual(str(u), 'oh no')

    def test_request_bad(self):
        """UAAError is raised when it occurs"""

        r = Mock()
        r.status_code = 500
        r.text = json.dumps({'error_description': 'oh no'})
        self.requests.get.return_value = r

        with self.assertRaises(UAAError):
            self.uaac._request('/bar', 'GET')

        self.requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer a-client-token'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

    def test_request_get(self):
        """GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        self.requests.get.return_value = r

        resp = self.uaac._request('/bar', 'GET')

        self.requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer a-client-token'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

        self.assertEqual(resp['test'], 'value')

    def test_request_get_insecure(self):
        """Insecure GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        self.requests.get.return_value = r

        self.uaac.verify_tls = False

        resp = self.uaac._request('/bar', 'GET')

        self.requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer a-client-token'},
            json=None,
            params=None,
            auth=None,
            verify=False
        )

        self.assertEqual(resp['test'], 'value')

    def test_request_get_headers(self):
        """Additional headers are included if we provide them"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        self.requests.get.return_value = r

        resp = self.uaac._request('/bar', 'GET', headers={'omg': 'lol'})

        self.requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'omg': 'lol', 'Authorization': 'Bearer a-client-token'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

        self.assertEqual(resp['test'], 'value')

    def test_request_get_params(self):
        """Query string is sent if params are provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        self.requests.get.return_value = r

        resp = self.uaac._request('/bar', 'GET', params={'omg': 'lol'})

        self.requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer a-client-token'},
            json=None,
            params={'omg': 'lol'},
            auth=None,
            verify=True
        )

        self.assertEqual(resp['test'], 'value')

    def test_request_get_auth(self):
        """Auth value is passed directly to requests"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        self.requests.get.return_value = r

        resp = self.uaac._request('/bar', 'GET', auth='this should be basic')

        self.requests.get.assert_called_with(
            'http://example.com/bar',
            headers={},
            json=None,
            params=None,
            auth='this should be basic',
            verify=True
        )

        self.assertEqual(resp['test'], 'value')

    def test_request_post_body(self):
        """Body is included in request if provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        self.requests.post.return_value = r

        resp = self.uaac._request('/bar', 'POST', body='hi')

        self.requests.post.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer a-client-token'},
            json='hi',
            params=None,
            auth=None,
            verify=True
        )

        self.assertEqual(resp['test'], 'value')

    def test_idps(self):
        """idps() makes a GET request to /identity-providers"""

        m = Mock()
        self.uaac._request = m

        self.uaac.idps(active_only=True)
        m.assert_called_with('/identity-providers', 'GET', params={'active_only': 'true'})

        self.uaac.idps(active_only=False)
        m.assert_called_with('/identity-providers', 'GET', params={'active_only': 'false'})

    def test_users(self):
        """users() makes a GET request to /Users"""

        m = Mock()
        self.uaac._request = m

        self.uaac.users()
        m.assert_called_with('/Users', 'GET', params={'startIndex': 1})

        self.uaac.users(start=2)
        m.assert_called_with('/Users', 'GET', params={'startIndex': 2})

        self.uaac.users(list_filter='test filter')
        m.assert_called_with('/Users', 'GET',
                             params={'filter': 'test filter', 'startIndex': 1})

    def test_get_user(self):
        """get_user() makes a GET request to /Users/<id>"""

        m = Mock()
        self.uaac._request = m

        self.uaac.get_user('foo')
        m.assert_called_with(urljoin('/Users', 'foo'), 'GET')

    def test_put_user(self):
        """put_user() makes a PUT request to /Users/<id> with appropriate headers"""

        m = Mock()
        self.uaac._request = m

        user = {
            'id': 'foo',
            'meta': {
                'version': '123'
            }
        }

        self.uaac.put_user(user)

        m.assert_called_with(
            urljoin('/Users', 'foo'),
            'PUT',
            body=user,
            headers={'If-Match': '123'}
        )

    def test_invite_users(self):
        """invite_users() makes a PUT request to /invite_users<id>"""

        m = Mock()
        self.uaac._request = m

        email = 'foo@example.com'
        redirect_uri = 'http://www.example.com'

        self.uaac.invite_users(email, redirect_uri)

        m.assert_called_with(
            '/invite_users',
            'POST',
            body={'emails': [email]},
            params={'redirect_uri': redirect_uri}
        )

    def test_oauth_token(self):
        """oauth_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        m = Mock()
        self.uaac._request = m

        self.uaac.oauth_token('foo')

        args, kwargs = m.call_args

        self.assertEqual(args, ('/oauth/token', 'POST'))

        self.assertEqual(kwargs['params'], {
            'code': 'foo',
            'grant_type': 'authorization_code',
            'response_type': 'token'
        })

    def test_get_client_token(self):
        """_get_client_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        m = Mock()
        self.uaac._request = m

        self.token_patch.stop()

        self.uaac._get_client_token()

        args, kwargs = m.call_args

        self.assertEqual(args, ('/oauth/token', 'POST'))

        self.assertEqual(kwargs['params'], {
            'grant_type': 'client_credentials',
            'response_type': 'token'
        })

        self.assertIsInstance(kwargs['auth'], HTTPBasicAuth)
        self.assertEqual(kwargs['auth'].username, 'client id')
        self.assertEqual(kwargs['auth'].password, 'client secret')

    def test_user_token(self):
        """user token functions store and decode tokens"""

        # None is returned if we don't have a token
        self.assertEqual(self.uaac.get_user_token(), None)

        # False is returned if we try to set a token with an invalid value
        self.assertEqual(self.uaac.set_user_token(None), False)

        # when we set a token, we get it back
        token_check = self.uaac.set_user_token(TEST_TOKEN)
        profile = self.uaac.get_user_token()
        self.assertEqual(token_check, profile)

        # token is decoded
        self.assertIn('scope', profile)
        self.assertIn('exp', profile)

    def test_change_password(self):
        """change_password() makes a PUT request to /Users/<id>/password"""

        m = Mock()
        self.uaac._request = m

        self.uaac.change_password('foo', 'bar', 'baz')

        m.assert_called_with(
            '/Users/foo/password',
            'PUT',
            body={
                'oldPassword': 'bar',
                'password': 'baz'
            }
        )

    def test_set_password_good(self):
        """set_password() makes a PUT request to /Users/<id>/password"""

        m = Mock()
        self.uaac._request = m
        self.uaac._request.return_value = {
            'resources': [
                {"id": "foo"}
            ]
        }

        self.assertTrue(self.uaac.set_password('foo', 'bar'))

        m.assert_called_with(
            '/Users/foo/password',
            'PUT',
            body={
                'password': 'bar'
            }
        )

    def test_set_password_bad(self):
        """set_password() does not call /Users<id>/password if user is not found"""

        m = Mock()
        self.uaac._request = m
        self.uaac._request.return_value = {
            'resources': []
        }

        self.assertFalse(self.uaac.set_password('foo', 'bar'))

        m.assert_called_once()

    def test_does_origin_user_exist_bad(self):
        """does_origin_user_exist() makes an expected scim query and returns false"""

        m = Mock()
        self.uaac._request = m
        self.uaac._request.return_value = {
            'resources': []
        }

        self.assertFalse(self.uaac.does_origin_user_exist('foo', 'bar'))

        m.assert_called_with(
            '/Users',
            'GET',
            params={
                'filter': 'userName eq "foo" and origin eq "bar"',
                'startIndex': 1
            }
        )

    def test_does_origin_user_exist_good(self):
        """does_origin_user_exist() returns true"""

        m = Mock()
        self.uaac._request = m
        self.uaac._request.return_value = {
            'resources': [{"id": "foo"}]
        }

        self.assertTrue(self.uaac.does_origin_user_exist('foo', 'bar'))
