from datetime import datetime, timedelta
from contextlib import contextmanager
import json
import random
import string
from posixpath import join as urljoin
import unittest

import flask
from flask import appcontext_pushed
from mock import Mock, patch
from requests.auth import HTTPBasicAuth

from uaaextras.webapp import create_app, send_email, str_to_bool, CONFIG_KEYS
from uaaextras.clients import UAAError, UAAClient

app = create_app({'UAA_CLIENT_ID': 'client-id', 'UAA_CLIENT_SECRET': 'client-secret'})


@contextmanager
def uaac_set(app, uaac=Mock()):
    """Shim in a mock object to flask.g"""
    def handler(sender, **kwargs):
        flask.g.uaac = uaac
    with appcontext_pushed.connected_to(handler, app):
        yield


class TestAppConfig(unittest.TestCase):
    def test_str_bool(self):
        """Strings are apprpriate converted to booleans"""

        assert str_to_bool('true') is True
        assert str_to_bool('1') is True
        assert str_to_bool(True) is True

        assert str_to_bool('0') is False
        assert str_to_bool(None) is False
        assert str_to_bool('false') is False

        assert str_to_bool('lol') is None

    def test_config_from_env_default(self):
        """The default config is loaded if config key isn't present"""

        app = create_app({})
        for kk, vv in CONFIG_KEYS.items():
            assert app.config[kk] == vv

    def test_config_from_env(self):
        """If an env var is set, then it is used as the config value"""

        # make env with random values
        fake_env = {}
        for kk in CONFIG_KEYS.keys():
            if kk == 'UAA_VERIFY_TLS':
                fake_env[kk] = random.choice([True, False])
            else:
                fake_env[kk] = ''.join(random.choice(string.ascii_uppercase) for _ in range(16))

        app = create_app(fake_env)
        # validate they all match
        for kk in CONFIG_KEYS.keys():
            assert app.config[kk] == fake_env[kk]

    @patch('uaaextras.webapp.smtplib')
    def test_send_email_no_auth(self, smtplib):
        """Email is sent as expected"""

        app = Mock()
        app.config = {
            'SMTP_FROM': 'bar@example.com',
            'SMTP_HOST': 'remote-host',
            'SMTP_PORT': 9160,
            'SMTP_USER': None,
            'SMTP_PASS': None
        }

        send_email(app, 'foo@example.com', 'da subject', 'body content')

        smtplib.SMTP.assert_called_with('remote-host', 9160)

        args = smtplib.SMTP().sendmail.call_args

        assert args[0][:2] == (app.config['SMTP_FROM'], ['foo@example.com'])
        assert args[0][2].endswith('body content')

        print(args[0][2])
        assert 'To: foo@example.com' in args[0][2]
        assert 'Subject: da subject' in args[0][2]

    @patch('uaaextras.webapp.smtplib')
    def test_send_email_auth(self, smtplib):
        """IF SMTP_USER and SMTP_PASS are provided, smtp.login() is called"""
        app = Mock()
        app.config = {
            'SMTP_FROM': 'bar@example.com',
            'SMTP_HOST': 'remote-host',
            'SMTP_PORT': 9160,
            'SMTP_USER': 'user',
            'SMTP_PASS': 'pass'
        }

        send_email(app, 'foo@example.com', 'da subject', 'body content')

        smtplib.SMTP.assert_called_with('remote-host', 9160)

        smtplib.SMTP().login.assert_called_with('user', 'pass')

    @patch('uaaextras.webapp.render_template')
    def test_csrf_token(self, render_template):
        """When a post request is made with a missing or invalid csrf token,
        the error/csrf.html template is displayed
        """

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'ssssshhhhhh'
                sess['UAA_TOKEN'] = 'foo'

            rv = c.post('/')
            assert rv.status_code == 400
            render_template.assert_called_with('error/csrf.html')

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.render_template')
    def test_uaa_token(self, render_template, uaac):
        """When we cannot validate a UAA token, the error/token_validation.html template is displayed"""

        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})
        uaac.side_effect = UAAError(r)

        render_template.return_value = 'template content'

        with app.test_client() as c:
            rv = c.get('/oauth/login')

            assert rv.status_code == 401
            render_template.assert_called_with('error/token_validation.html')

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.render_template')
    def test_uaa_scope(self, render_template, uaac):
        """When the token is valid, but the scope is incorrect, the error/missing_scope.html template is displayed"""

        uaac().oauth_token.return_value = {'scope': 'not.what.we.wanted'}

        render_template.return_value = 'template content'

        with app.test_client() as c:
            rv = c.get('/oauth/login?code=foo')

            assert rv.status_code == 403
            render_template.assert_called_with('error/missing_scope.html')

    @patch('uaaextras.webapp.render_template')
    def test_get_index(self, render_template):
        """When a GET request is made to /, the index.html template is displayed"""

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'

            rv = c.get('/')
            assert rv.status_code == 200
            render_template.assert_called_with('index.html')

    @patch('uaaextras.webapp.render_template')
    def test_get_invite(self, render_template):
        """When a GET request is made to /invite, the invite.html template is displayed"""

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'

            rv = c.get('/invite')
            assert rv.status_code == 200
            render_template.assert_called_with('invite.html')

    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.render_template')
    def test_invite_bad_email(self, render_template, flash):
        """When an email is blank or invalid, the error is flashed to the user"""

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': '', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('invite.html')
            flash.assert_called_once()

        flash.reset_mock()
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': 'not an email', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('invite.html')
            flash.assert_called_once()

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.render_template')
    def test_invite_error(self, render_template, uaac):
        """When an error occurs during the invite process, the error/internal.html template is displayed"""

        uaac().invite_users.return_value = {'failed_invites': [{'fail': 'here'}], 'new_invites': []}
        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 500
            print(uaac.invite_users())

            render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.smtplib')
    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.render_template')
    def test_invite_good(self, render_template, uaac, smtp):
        """When an invite is sucessfully sent, the invite_sent template is displayed"""

        uaac().invite_users.return_value = {'failed_invites': [], 'new_invites': [{'some': 'invite'}]}

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('invite_sent.html')

    @patch('uaaextras.webapp.session')
    def test_logout_good(self, session):
        """The session is cleared when logging out"""

        with app.test_request_context('/logout'):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess['UAA_TOKEN'] = 'foo'

                rv = c.get('/logout')
                assert rv.status_code == 302
                assert rv.location == 'http://localhost/'
                session.clear.assert_called_once()

    @patch('uaaextras.webapp.UAAClient')
    def test_uaac_is_created_from_session(self, uaac):
        """When a request is made, and a valid session exists g.uaac is created"""
        with app.test_request_context('/'):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess['UAA_TOKEN'] = 'foo'
                    sess['UAA_TOKEN_EXPIRES'] = datetime.utcnow() + timedelta(seconds=30)

                c.get('/')

                uaac.assert_called_with(app.config['UAA_BASE_URL'], 'foo', verify_tls=app.config['UAA_VERIFY_TLS'])

                assert isinstance(flask.g.uaac, Mock)

    @patch('uaaextras.webapp.UAAClient')
    def test_redirect_to_uaac(self, uaac):
        """When a request is made, and no session exists, redirect to UAAC Oauth"""
        with app.test_client() as c:
            rv = c.get('/')

            assert rv.status_code == 302
            target = app.config['UAA_BASE_URL'] + '/oauth/authorize?client_id=' + app.config['UAA_CLIENT_ID']
            target += '&response_type=code'
            assert rv.location == target

    @patch('uaaextras.webapp.UAAClient')
    def test_oauth_creates_session(self, uaac):
        """/oauth/login validates codes with UAA"""

        uaac().oauth_token.return_value = {'access_token': 'foo', 'expires_in': 30, 'scope': 'scim.invite'}

        with app.test_request_context('/oauth/login'):
            with app.test_client() as c:
                c.get('/oauth/login?code=123')

                assert uaac.oauth_token.called_with('123', app.config['UAA_CLIENT_ID'], app.config['UAA_CLIENT_SECRET'])

                assert flask.session['UAA_TOKEN'] == 'foo'
                assert flask.session['UAA_TOKEN_SCOPES'] == ['scim.invite']


class TestUAAClient(unittest.TestCase):
    """Test our UAA Client"""
    def test_error_message(self):
        """Error messages are populated properly in the exception"""
        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        u = UAAError(r)
        assert str(u) == 'oh no'

    @patch('uaaextras.clients.uaa.requests')
    def test_request_bad(self, requests):
        """UAAError is reaised when it occurs"""

        r = Mock()
        r.status_code = 500
        r.text = json.dumps({'error_description': 'oh no'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', True)

        with self.assertRaises(UAAError):
            uaac._request('/bar', 'GET')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

    @patch('uaaextras.clients.uaa.requests')
    def test_request_get(self, requests):
        """GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', True)

        resp = uaac._request('/bar', 'GET')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=True
        )

        assert resp['test'] == 'value'

    @patch('uaaextras.clients.uaa.requests')
    def test_request_get_insecure(self, requests):
        """Insecure GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaaextras.clients.uaa.requests')
    def test_request_get_headers(self, requests):
        """Additional headers are included if we provide them"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET', headers={'omg': 'lol'})

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'omg': 'lol', 'Authorization': 'Bearer foo'},
            json=None,
            params=None,
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaaextras.clients.uaa.requests')
    def test_request_get_params(self, requests):
        """Query string is sent if params are provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET', params={'omg': 'lol'})

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json=None,
            params={'omg': 'lol'},
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaaextras.clients.uaa.requests')
    def test_request_get_auth(self, requests):
        """Auth value is passed directly to requests"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.get.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'GET', auth='this should be basic')

        requests.get.assert_called_with(
            'http://example.com/bar',
            headers={},
            json=None,
            params=None,
            auth='this should be basic',
            verify=False
        )

        assert resp['test'] == 'value'

    @patch('uaaextras.clients.uaa.requests')
    def test_request_post_body(self, requests):
        """Body is included in request if provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({'test': 'value'})
        requests.post.return_value = r

        uaac = UAAClient('http://example.com', 'foo', False)

        resp = uaac._request('/bar', 'POST', body='hi')

        requests.post.assert_called_with(
            'http://example.com/bar',
            headers={'Authorization': 'Bearer foo'},
            json='hi',
            params=None,
            auth=None,
            verify=False
        )

        assert resp['test'] == 'value'

    def test_idps(self):
        """idps() makes a GET request to /identity-providers"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.idps(active_only=True)
        m.assert_called_with('/identity-providers', 'GET', params={'active_only': 'true'})

        uaac.idps(active_only=False)
        m.assert_called_with('/identity-providers', 'GET', params={'active_only': 'false'})

    def test_users(self):
        """users() makes a GET request to /Users"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.users()
        m.assert_called_with('/Users', 'GET', params=None)

        uaac.users('test filter')
        m.assert_called_with('/Users', 'GET', params={'filter': 'test filter'})

    def test_get_user(self):
        """get_user() makes a GET request to /Users/<id>"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.get_user('foo')
        m.assert_called_with(urljoin('/Users', 'foo'), 'GET')

    def test_put_user(self):
        """put_user() makes a PUT request to /Users/<id> with appropriate headers"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        user = {
            'id': 'foo',
            'meta': {
                'version': '123'
            }
        }

        uaac.put_user(user)

        m.assert_called_with(
            urljoin('/Users', 'foo'),
            'PUT',
            body=user,
            headers={'If-Match': '123'}
        )

    def test_invite_users(self):
        """invite_users() makes a PUT request to /invite_users<id>"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        email = 'foo@bar.baz'
        redirect_uri = 'http://www.example.com'

        uaac.invite_users(email, redirect_uri)

        m.assert_called_with(
            '/invite_users',
            'POST',
            body={'emails': [email]},
            params={'redirect_uri': redirect_uri}
        )

    def test_oauth_token(self):
        """oauth_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.oauth_token('foo', 'bar', 'baz')

        args, kwargs = m.call_args

        assert args == ('/oauth/token', 'POST')

        assert kwargs['params'] == {
            'code': 'foo',
            'grant_type': 'authorization_code',
            'response_type': 'token'
        }

        assert isinstance(kwargs['auth'], HTTPBasicAuth)
        assert kwargs['auth'].username == 'bar'
        assert kwargs['auth'].password == 'baz'

    def test_decode_access_token(self):
        """decode_access_token() does a base64 decode of the JWT auth token data to get profile information"""
        uaac = UAAClient('http://example.com', 'foo', False)
        token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiI5OWNiZGM4ZGE2MTg0ZmMyODgxYzUwYWNhYzJjZTJjNiIsInN1YiI6ImFkbWluIiwiYXV0aG9yaXRpZXMiOlsiY2xpZW50cy5yZWFkIiwicGFzc3dvcmQud3JpdGUiLCJjbGllbnRzLnNlY3JldCIsImNsaWVudHMud3JpdGUiLCJ1YWEuYWRtaW4iLCJzY2ltLndyaXRlIiwic2NpbS5yZWFkIl0sInNjb3BlIjpbImNsaWVudHMucmVhZCIsInBhc3N3b3JkLndyaXRlIiwiY2xpZW50cy5zZWNyZXQiLCJjbGllbnRzLndyaXRlIiwidWFhLmFkbWluIiwic2NpbS53cml0ZSIsInNjaW0ucmVhZCJdLCJjbGllbnRfaWQiOiJhZG1pbiIsImNpZCI6ImFkbWluIiwiYXpwIjoiYWRtaW4iLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImQ1NjA4NGZkIiwiaWF0IjoxNDc4Mjc5NTM3LCJleHAiOjE0NzgzMjI3MzcsImlzcyI6Imh0dHBzOi8vdWFhLmNsb3VkLmdvdi9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJzY2ltIiwicGFzc3dvcmQiLCJjbGllbnRzIiwidWFhIiwiYWRtaW4iXX0.uJABuxWIc3p-p3zJol1i2BHBfDkKXnpIcCFbOvDg8WGdbrufhFZjk78uRiPk8sw9I0reUbjyLeo0-0Eqg-x49pVaNpNeheDYaz2oc_CMO13MPXlCtVHdEGnq4e6NV21wxTMVmrLhP0QscDRctnITUY7c-ywMsUrXgv7VFj-9GPZjfr-PyG01OxStrAfe06kTXKbEHIHFgfidrDYA_pTnPO1LPz5HllVQUkAdlIIEx6VshBW6_4l2Sm0nof3cVOxqMUUB6xLSJARfudPrCmFeUIdnICl85T00-1kOe2YUMm9xRHS4hnBYbM6IU5JDmzvnz3ANEM2Uzmzv9JzkJjboIQ"  # noqa: E501
        profile = uaac.decode_access_token(token)

        assert 'scope' in profile
        assert 'exp' in profile
