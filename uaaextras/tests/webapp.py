from datetime import datetime, timedelta
import json
import random
import string
import unittest

import flask
from mock import Mock, patch

from uaaextras.clients import UAAError
from uaaextras.webapp import create_app, CONFIG_KEYS, generate_csrf_token
from uaaextras.utils import str_to_bool, generate_password

TEST_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiI5OWNiZGM4ZGE2MTg0ZmMyODgxYzUwYWNhYzJjZTJjNiIsInN1YiI6ImFkbWluIiwiYXV0aG9yaXRpZXMiOlsiY2xpZW50cy5yZWFkIiwicGFzc3dvcmQud3JpdGUiLCJjbGllbnRzLnNlY3JldCIsImNsaWVudHMud3JpdGUiLCJ1YWEuYWRtaW4iLCJzY2ltLndyaXRlIiwic2NpbS5yZWFkIl0sInNjb3BlIjpbImNsaWVudHMucmVhZCIsInBhc3N3b3JkLndyaXRlIiwiY2xpZW50cy5zZWNyZXQiLCJjbGllbnRzLndyaXRlIiwidWFhLmFkbWluIiwic2NpbS53cml0ZSIsInNjaW0ucmVhZCJdLCJjbGllbnRfaWQiOiJhZG1pbiIsImNpZCI6ImFkbWluIiwiYXpwIjoiYWRtaW4iLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImQ1NjA4NGZkIiwiaWF0IjoxNDc4Mjc5NTM3LCJleHAiOjE0NzgzMjI3MzcsImlzcyI6Imh0dHBzOi8vdWFhLmNsb3VkLmdvdi9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJzY2ltIiwicGFzc3dvcmQiLCJjbGllbnRzIiwidWFhIiwiYWRtaW4iXX0.uJABuxWIc3p-p3zJol1i2BHBfDkKXnpIcCFbOvDg8WGdbrufhFZjk78uRiPk8sw9I0reUbjyLeo0-0Eqg-x49pVaNpNeheDYaz2oc_CMO13MPXlCtVHdEGnq4e6NV21wxTMVmrLhP0QscDRctnITUY7c-ywMsUrXgv7VFj-9GPZjfr-PyG01OxStrAfe06kTXKbEHIHFgfidrDYA_pTnPO1LPz5HllVQUkAdlIIEx6VshBW6_4l2Sm0nof3cVOxqMUUB6xLSJARfudPrCmFeUIdnICl85T00-1kOe2YUMm9xRHS4hnBYbM6IU5JDmzvnz3ANEM2Uzmzv9JzkJjboIQ"  # noqa: E501


def make_app():
    return create_app({
        'UAA_CLIENT_ID': 'client-id',
        'UAA_CLIENT_SECRET': 'client-secret',
        'PW_EXPIRES_DAYS': 90,
        'PW_EXPIRATION_WARN_DAYS': 5
    })


@patch('uaaextras.webapp.UAAClient', Mock())
@patch('uaaextras.webapp.StrictRedis', Mock())
class TestAppConfig(unittest.TestCase):
    def test_str_bool(self):
        """Strings are apprpriate converted to booleans"""

        self.assertTrue(str_to_bool('true'))
        self.assertTrue(str_to_bool('1'))
        self.assertTrue(str_to_bool(True))

        self.assertFalse(str_to_bool('0'))
        self.assertFalse(str_to_bool(None))
        self.assertFalse(str_to_bool('false'))

        self.assertIsNone(str_to_bool('lol'))

    def test_config_from_env_default(self):
        """The default config is loaded if config key isn't present"""

        app = create_app({})
        for kk, vv in CONFIG_KEYS.items():
            self.assertEqual(app.config[kk], vv)

    def test_config_from_env(self):
        """If an env var is set, then it is used as the config value"""

        # make env with random values
        fake_env = {}
        for kk, vv in CONFIG_KEYS.items():
            if kk == 'UAA_VERIFY_TLS':
                fake_env[kk] = random.choice([True, False])
            elif kk == 'VALID_DOMAIN_LIST':
                fake_env[kk] = vv
                continue
            else:
                fake_env[kk] = ''.join(random.choice(string.ascii_uppercase) for _ in range(16))

        app = create_app(fake_env)
        # validate they all match
        for kk in CONFIG_KEYS.keys():
            self.assertEqual(app.config[kk], fake_env[kk])

    def test_generate_password(self):
        """Generate password returns a password with a defined length"""
        self.assertEqual(len(generate_password(24)), 24)
        self.assertEqual(len(generate_password(32)), 32)

    def test_vcap_application(self):
        """config is loaded from VCAP_APPLICATION"""
        app = create_app({
            "VCAP_APPLICATION": json.dumps({"uris": ['omg']})
        })

        self.assertEqual(app.config['SERVER_NAME'], 'omg')
        self.assertEqual(app.config['PREFERRED_URL_SCHEME'], 'https')

    def test_vcap_services(self):
        """redis config is loaded from VCAP_SERVICES"""
        app = create_app({
            "VCAP_SERVICES": json.dumps({
                "redis28": [{
                    "credentials": {
                        "hostname": "redis-host",
                        "password": "redis-pass",
                        "port": "916"
                    }
                }]
            })
        })

        self.assertEqual(app.config['REDIS_PARAMS']['host'], 'redis-host')
        self.assertEqual(app.config['REDIS_PARAMS']['port'], 916)
        self.assertEqual(app.config['REDIS_PARAMS']['password'], 'redis-pass')


@patch('uaaextras.webapp.StrictRedis', Mock())
@patch('uaaextras.webapp.UAAClient')
class TestAppAuthentication(unittest.TestCase):

    def setUp(self):
        self.app = make_app()
        self.c = self.app.test_client()

        self.render_template = Mock()
        self.render_template.return_value = 'template output'
        self.render_patch = patch('uaaextras.webapp.render_template', self.render_template)
        self.render_patch.start()

    def tearDown(self):
        self.render_patch.stop()

    @patch('uaaextras.webapp.session')
    def test_csrf_generate_reuse(self, session, uaac):
        """If a token is already in the session it's returned"""
        # we generate a token if we don't have one

        session.__getitem__.return_value = 'foo'
        session.__contains__.return_value = True

        token = generate_csrf_token()
        session.__getitem__.assert_called_with('_csrf_token')
        self.assertEqual(token, 'foo')

    @patch('uaaextras.webapp.session')
    def test_csrf_generate(self, session, uaac):
        """Calling generate_csrf_token() adds it to the session"""

        session.__contains__.return_value = False

        generate_csrf_token()
        session.__getitem__.assert_called_with('_csrf_token')
        session.__setitem__.assert_called_once()

    def test_csrf_token(self, uaac):
        """When a post request is made with a missing or invalid csrf token,
        the error/csrf.html template is displayed
        """

        with self.c.session_transaction() as sess:
            sess['_csrf_token'] = 'ssssshhhhhh'
            sess['UAA_TOKEN'] = 'foo'

        rv = self.c.post('/')
        self.assertEqual(rv.status_code, 400)
        self.render_template.assert_called_with('error/csrf.html')

    def test_uaa_token(self, uaac):
        """When we cannot validate a UAA token, the error/token_validation.html template is displayed"""

        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        uaac().oauth_token.side_effect = UAAError(r)

        rv = self.c.get('/oauth/login?code=cn916')

        self.assertEqual(rv.status_code, 401)
        self.render_template.assert_called_with('error/token_validation.html')

    def test_uaa_scope(self, uaac):
        """When the token is valid, but the scope is incorrect, the error/missing_scope.html template is displayed"""

        uaac().oauth_token.return_value = {'scope': 'not.what.we.wanted'}

        rv = self.c.get('/oauth/login?code=foo')

        self.assertEqual(rv.status_code, 403)
        self.render_template.assert_called_with('error/missing_scope.html')

    def test_uaac_is_created_from_session(self, uaac):
        """When a request is made, and a valid session exists g.uaac is created"""

        with self.app.test_request_context('/'):
            with self.app.test_client() as c:
                with c.session_transaction() as sess:
                    sess['UAA_TOKEN'] = 'foo'
                    sess['UAA_TOKEN_EXPIRES'] = datetime.utcnow() + timedelta(seconds=30)

                c.get('/')

                uaac().set_user_token.assert_called_with('foo')

                assert isinstance(flask.g.uaac, Mock)

    def test_redirect_to_uaac(self, uaac):
        """When a request is made, and no session exists, redirect to UAAC Oauth"""
        rv = self.c.get('/')

        self.assertEqual(rv.status_code, 302)
        target = self.app.config['UAA_BASE_URL'] + '/oauth/authorize?client_id=' + self.app.config['UAA_CLIENT_ID']
        target += '&response_type=code'

        self.assertEqual(rv.location, target)

    def test_oauth_creates_session(self, uaac):
        """/oauth/login validates codes with UAA"""

        uaac().oauth_token.return_value = {'access_token': 'foo', 'expires_in': 30, 'scope': 'scim.invite'}

        with self.app.test_request_context('/oauth/login'):
            with self.app.test_client() as c:
                c.get('/oauth/login?code=123')

                assert uaac.oauth_token.called_with(
                    '123',
                    self.app.config['UAA_CLIENT_ID'],
                    self.app.config['UAA_CLIENT_SECRET']
                )

                self.assertEqual(flask.session['UAA_TOKEN'], 'foo')
                self.assertEqual(flask.session['UAA_TOKEN_SCOPES'], ['scim.invite'])


class TestAppAuthenticatedPages(unittest.TestCase):
    """Test pages that require a user to be authenticated"""
    def setUp(self):
        self.render_template = Mock()
        self.render_template.return_value = 'template output'
        self.render_patch = patch('uaaextras.webapp.render_template', self.render_template)
        self.render_patch.start()

        self.redis = Mock()
        self.redis_patch = patch('uaaextras.webapp.StrictRedis', Mock(return_value=self.redis))
        self.redis_patch.start()

        self.app = make_app()
        self.c = self.app.test_client()

        with self.c.session_transaction() as sess:
            sess['UAA_TOKEN'] = TEST_TOKEN
            sess['_csrf_token'] = 'bar'

    def tearDown(self):
        self.render_patch.stop()
        self.redis_patch.stop()

    def test_get_index(self):
        """When a GET request is made to /, the index.html template is displayed"""

        rv = self.c.get('/')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('index.html')

    def test_get_invite(self):
        """When a GET request is made to /invite, the invite.html template is displayed"""

        rv = self.c.get('/invite')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('invite.html')

    @patch('uaaextras.webapp.flash')
    def test_invite_blank_email(self, flash):
        """When an email is blank, the error is flashed to the user"""

        rv = self.c.post('/invite', data={'email': '', '_csrf_token': 'bar'})
        self.render_template.assert_called_with('invite.html')
        flash.assert_called_once()
        self.assertEqual(rv.status_code, 200)

    @patch('uaaextras.webapp.flash')
    def test_invite_bad_email(self, flash):
        """When an email is invalid, the error is flashed to the user"""

        rv = self.c.post('/invite', data={'email': 'not an email', '_csrf_token': 'bar'})
        self.render_template.assert_called_with('invite.html')
        flash.assert_called_once()
        self.assertEqual(rv.status_code, 200)

    @patch('uaaextras.webapp.UAAClient')
    def test_invite_error(self, uaac):
        """When an error occurs during the invite process, the error/internal.html template is displayed"""

        uaac().does_origin_user_exist.side_effect = Exception()

        rv = self.c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
        self.render_template.assert_called_with('error/internal.html')
        self.assertEqual(rv.status_code, 500)

    @patch('uaaextras.webapp.UAAClient')
    def test_invite_unknown_uaaerror(self, uaac):
        """When an error occurs during the invite process, the error/internal.html template is displayed"""
        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        uaac().does_origin_user_exist.side_effect = UAAError(r)

        rv = self.c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
        self.render_template.assert_called_with('error/internal.html')
        self.assertEqual(rv.status_code, 500)

    @patch('uaaextras.webapp.UAAClient')
    def test_invite_bad_token(self, uaac):
        """When an error occurs during the invite process, the error/internal.html template is displayed"""
        r = Mock()
        r.text = json.dumps({'error_description': 'Invalid access token'})

        uaac().does_origin_user_exist.side_effect = UAAError(r)

        rv = self.c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 302)

    @patch('uaaextras.webapp.Emailer')
    @patch('uaaextras.webapp.UAAClient')
    def test_invite_good(self, uaac, emailer):
        """When an invite is sucessfully sent, the invite_sent template is displayed"""

        uaac().invite_users.return_value = {
            'failed_invites': [],
            'new_invites': [{'inviteLink': 'testLink', 'some': 'invite'}]
        }
        uaac().does_origin_user_exist.return_value = False
        emailer().validate_email.return_value = 'foo@example.com'

        rv = self.c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
        self.render_template.assert_called_with('invite_sent.html')
        self.assertEqual(rv.status_code, 200)

        args = self.redis.setex.call_args

        # our key and expiration were set correctly in redis
        self.assertEqual(args[0][-2], self.app.config['UAA_INVITE_EXPIRATION_IN_SECONDS'])
        self.assertEqual(args[0][-1], 'testLink')

        # we sent the email
        emailer().send_email.assert_called_with('foo@example.com', 'template output', 'template output')

    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.UAAClient')
    def test_invite_user_exists(self, uaac, flash):
        """When an user already exists during invite process, the invite.html template is displayed"""

        uaac().does_origin_user_exist.return_value = True

        rv = self.c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('invite.html')
        flash.assert_called_once()

    @patch('uaaextras.webapp.UAAClient', Mock())
    @patch('uaaextras.webapp.session')
    def test_logout_good(self, session):
        """The session is cleared when logging out"""

        rv = self.c.get('/logout')
        self.assertEqual(rv.status_code, 302)
        self.assertEqual(rv.location, 'http://localhost:5000/')
        session.clear.assert_called_once()

    def test_get_change_password(self):
        """ When a GET request is made to /change-password,
            the change_password.html template is displayed
        """

        rv = self.c.get('/change-password')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')

    @patch('uaaextras.webapp.flash')
    def test_change_password_same(self, flash):
        """Old password cannot equal new password"""

        rv = self.c.post('/change-password', data={'old_password': 'foo', 'new_password': 'foo', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')
        flash.assert_called()

    @patch('uaaextras.webapp.flash')
    def test_change_password_old_blank(self, flash):
        """Old password cannot be blank"""

        rv = self.c.post('/change-password', data={'old_password': '', 'new_password': 'foo', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')
        flash.assert_called()

    @patch('uaaextras.webapp.flash')
    def test_change_password_new_blank(self, flash):
        """New password cannot be blank"""

        rv = self.c.post('/change-password', data={'old_password': 'foo', 'new_password': '', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')
        flash.assert_called()

    @patch('uaaextras.webapp.flash')
    def test_change_password_repeat_blank(self, flash):
        """Repeat password cannot be blank"""

        rv = self.c.post('/change-password', data={'old_password': 'foo', 'new_password': 'foo', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')
        flash.assert_called()

    @patch('uaaextras.webapp.flash')
    def test_change_password_no_match(self, flash):
        """passwords must match"""

        rv = self.c.post('/change-password', data={
            'old_password': 'foo',
            'new_password': 'foo',
            'repeat_password': 'bar',
            '_csrf_token': 'bar'
        })

        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')
        flash.assert_called()

    @patch('uaaextras.webapp.UAAClient')
    def test_change_password_general_error(self, uaac):
        """When an unexpected error is occured, 500 is returned"""

        uaac().change_password.side_effect = Exception

        rv = self.c.post('/change-password', data={
            'old_password': 'bar',
            'new_password': 'foo',
            'repeat_password': 'foo',
            '_csrf_token': 'bar'
        })

        self.assertEqual(rv.status_code, 500)
        self.render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.flash')
    def test_change_password_uaa_error(self, flash, uaac):
        """UAA error messages are displayed"""

        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        uaac().change_password.side_effect = UAAError(r)

        rv = self.c.post('/change-password', data={
            'old_password': 'bar',
            'new_password': 'foo',
            'repeat_password': 'foo',
            '_csrf_token': 'bar'
        })

        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('change_password.html')
        flash.assert_called()

    @patch('uaaextras.webapp.UAAClient')
    def test_change_password_good(self, uaac):
        """Password can be changed"""

        uaac().get_user_token.return_value = {
            "user_id": "user-id"
        }

        rv = self.c.post('/change-password', data={
            'old_password': 'bar',
            'new_password': 'foo',
            'repeat_password': 'foo',
            '_csrf_token': 'bar'
        })

        self.assertEqual(rv.status_code, 200)
        uaac().change_password.assert_called_with('user-id', 'bar', 'foo')
        self.render_template.assert_called_with('password_changed.html')

    @patch('uaaextras.webapp.UAAClient')
    def test_first_login_with_idp_provider(self, uaac):
        """ When a GET request is made to /first-login,
            the user is redirected to IDP_PROVIDER_URL with an origin of 'uaa'
        """
        user = {
            'origin': 'uaa',
            'userName': 'testUser'
        }

        uaac().get_user.return_value = user

        rv = self.c.get('/first-login')
        self.assertEqual(rv.status_code, 302)
        self.assertEqual(rv.location, self.app.config['IDP_PROVIDER_URL'])

        # validate we updated the users' origin
        uaac().put_user.assert_called_with({'userName': 'testUser', 'origin': 'idp.com', 'externalId': 'testUser'})

    @patch('uaaextras.webapp.UAAClient')
    def test_first_login_with_uaa_provider(self, uaac):
        """ When a GET request is made to /first-login,
            the user is redirected to UAA_BASE_URL with an origin other
            than 'uaa'.
        """

        user = {
            'origin': 'example',
            'userName': 'testUser'
        }

        uaac().decode_access_token.return_value = {
            'user_id': 'example'
        }
        uaac().get_user.return_value = user

        rv = self.c.get('/first-login')
        self.assertEqual(rv.status_code, 302)
        self.assertEqual(rv.location, self.app.config['UAA_BASE_URL'])


class TestAppUnAuthenticatedPages(unittest.TestCase):
    """Test pages that can be accessed without authenticating"""
    def setUp(self):
        self.render_template = Mock()
        self.render_template.return_value = 'template output'
        self.render_patch = patch('uaaextras.webapp.render_template', self.render_template)
        self.render_patch.start()

        self.redis = Mock()
        self.redis_patch = patch('uaaextras.webapp.StrictRedis', Mock(return_value=self.redis))
        self.redis_patch.start()

        self.app = make_app()
        self.c = self.app.test_client()
        with self.c.session_transaction() as sess:
            sess['_csrf_token'] = 'bar'
            print("SETTING UP SESSION")

    def tearDown(self):
        self.render_patch.stop()
        self.redis_patch.stop()

    def test_get_signup(self):
        """When a GET request is made to /signup, the signup.html template is displayed"""

        rv = self.c.get('/signup')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('signup.html')

    @patch('uaaextras.webapp.flash')
    def test_signup_blank_email(self, flash):
        """When an email is blank or invalid, or not federal gov, the error is flashed to the user"""

        rv = self.c.post('/signup', data={'email': '', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('signup.html')
        flash.assert_called_once()

    @patch('uaaextras.webapp.flash')
    def test_signup_bad_email(self, flash):
        """When an email is blank or invalid, or not federal gov, the error is flashed to the user"""

        rv = self.c.post('/signup', data={'email': 'not an email', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('signup.html')
        flash.assert_called_once()

    @patch('uaaextras.webapp.flash')
    def test_signup_invalid_email(self, flash):
        rv = self.c.post('/signup', data={'email': 'foo@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)

        self.render_template.assert_called_with('signup.html')
        flash.assert_called_once()

    @patch('uaaextras.webapp.UAAClient')
    def test_signup_error(self, uaac):
        """When an error occurs during the signup process, the error/internal.html template is displayed"""

        uaac().invite_users.return_value = {'failed_invites': [{'fail': 'here'}], 'new_invites': []}
        uaac().does_origin_user_exist.return_value = False

        rv = self.c.post('/signup', data={'email': 'cloud-gov-notifications@gsa.gov', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 500)

        self.render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.Emailer')
    @patch('uaaextras.webapp.UAAClient')
    def test_signup_good(self, uaac, emailer):
        """When an signup is sucessfully sent, the signup_invite_sent template is displayed"""

        uaac().invite_users.return_value = {
            'failed_invites': [],
            'new_invites': [{'inviteLink': 'testLink', 'some': 'invite'}]
        }
        uaac().does_origin_user_exist.return_value = False
        emailer().validate_email.return_value = 'foo@example.com'

        rv = self.c.post('/signup', data={'email': 'test@example.com', '_csrf_token': 'bar'})
        self.render_template.assert_called_with('signup_sent.html')
        self.assertEqual(rv.status_code, 200)

        args = self.redis.setex.call_args
        # our key and expiration were set correctly in redis
        self.assertEqual(args[0][-2], self.app.config['UAA_INVITE_EXPIRATION_IN_SECONDS'])
        self.assertEqual(args[0][-1], 'testLink')

        # we sent the email
        emailer().send_email.assert_called_with('foo@example.com', 'template output', 'template output')

    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.UAAClient')
    def test_signup_user_exists(self, uaac, flash):
        """When an user already exists during signup process, the signup.html template is displayed"""

        uaac().does_origin_user_exist.return_value = True

        rv = self.c.post('/signup', data={'email': 'foo@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('signup.html')
        flash.assert_called_once()

    def test_get_forgot_password(self):
        """ When a GET request is made to /forgot-password,
            the forgot_password.html template is displayed
        """

        rv = self.c.get('/forgot-password')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('forgot_password.html')

    def test_no_redis_forgot_password(self):
        """ When submitting an email and redis is down, server responsds 500"""

        self.redis.return_value = Exception()

        rv = self.c.post('/forgot-password', data={'email_address': 'test@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 500)
        self.render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.Emailer')
    def test_good_forgot_password(self, emailer):
        """ When submitting an email, the email and token are set in the Redis DB
        """

        emailer().validate_email.return_value = 'test@example.com'

        rv = self.c.post('/forgot-password', data={'email_address': 'test@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)

        args = self.redis.setex.call_args
        # our key and expiration were set correctly in redis
        self.assertEqual(args[0][0], 'test@example.com')
        self.assertEqual(args[0][-2], self.app.config['FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS'])

        self.render_template.assert_called_with(
            'forgot_password.html',
            email_sent=True,
            email='test@example.com'
        )

    @patch('uaaextras.webapp.flash')
    def test_forgot_password_invalid_email(self, flash):
        rv = self.c.post('/forgot-password', data={'email_address': 'thats-no-email', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)

        self.render_template.assert_called_with('forgot_password.html')
        flash.assert_called_once()

    @patch('uaaextras.webapp.flash')
    def test_reset_password_invalid_email(self, flash):
        rv = self.c.post('/reset-password', data={'email_address': 'thats-no-email', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 200)

        self.render_template.assert_called_with('reset_password.html')
        flash.assert_called_once()

    @patch('uaaextras.webapp.UAAClient')
    def test_reset_password_general_error(self, uaac):
        """When an unexpected error is occured, 500 is returned"""

        uaac().set_password.side_effect = Exception

        generate_password.return_value = 'temp-password'

        self.redis.get.return_value = b'example'

        rv = self.c.post(
            '/reset-password',
            data={
                'email_address': 'test@example.com',
                '_validation_code': 'example',
                '_csrf_token': 'bar'
            }
        )

        self.assertEqual(rv.status_code, 500)
        self.render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.flash')
    def test_reset_password_uaa_error(self, flash, uaac):
        """UAA error messages are displayed"""

        r = Mock()
        r.text = json.dumps({'error_description': 'oh no'})

        uaac().set_password.side_effect = UAAError(r)

        generate_password.return_value = 'temp-password'

        self.redis.get.return_value = b'example'

        rv = self.c.post(
            '/reset-password',
            data={
                'email_address': 'test@example.com',
                '_validation_code': 'example',
                '_csrf_token': 'bar'
            }
        )

        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('reset_password.html')
        flash.assert_called()

    def test_get_reset_password(self):
        """ When a GET request is made to /reset-password,
            and the validation code is passed in correctly
            the reset_password.html template is displayed
        """

        rv = self.c.get('/reset-password?validation=foo')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('reset_password.html', validation_code='foo')

    @patch('uaaextras.webapp.flash')
    def test_get_reset_password_bad_code(self, flash):
        """ When a GET request is made to /reset-password,
            and the validation code is not passed in correctly
            the reset_password.html template is displayed
            and error message is put in flash
        """

        rv = self.c.get('/reset-password')
        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('reset_password.html', validation_code=None)
        flash.assert_called_once()

    def test_no_redis_reset_password(self):
        """ When submitting an email and redis is down, server responsds 500
        """

        self.redis.ping.side_effect = Exception()

        rv = self.c.post('/reset-password', data={'email_address': 'test@example.com', '_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 500)
        self.render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.generate_password')
    @patch('uaaextras.webapp.UAAClient')
    def test_render_temporary_password(self, uaac, generate_password):
        """ When submitting an email and a valid token, we should render a temporary password.
        """

        generate_password.return_value = 'temp-password'

        self.redis.get.return_value = b'example'

        rv = self.c.post(
            '/reset-password',
            data={
                'email_address': 'test@example.com',
                '_validation_code': 'example',
                '_csrf_token': 'bar'
            }
        )

        self.assertEqual(rv.status_code, 200)
        self.redis.get.assert_called_with('test@example.com')
        self.redis.delete.assert_called_with('test@example.com')
        self.render_template.assert_called_with('reset_password.html', password='temp-password')
        uaac().set_password.asset_called_with('test@example.com', 'temp-password')

    @patch('uaaextras.webapp.flash')
    def test_fail_to_render_temporary_password(self, flash):
        """ When submitting an email without a valid token, I should see a flash error message.
        """

        self.redis.get.return_value = b'example'

        rv = self.c.post(
            '/reset-password',
            data={
                'email_address': 'test@example.com',
                '_validation_code': 'not-example',
                '_csrf_token': 'bar'
            }
        )

        self.assertEqual(rv.status_code, 200)
        self.redis.get.assert_called_with('test@example.com')
        self.render_template.assert_called_with('reset_password.html')
        flash.assert_called_once()

    def test_redeem_no_verification_code(self):
        """When an redeem link is rendered, fail if there is no matching verification code"""

        self.redis.get.return_value = None

        rv = self.c.get('/redeem-invite')
        self.assertEqual(rv.status_code, 401)
        self.render_template.assert_called_with('error/token_validation.html')

    def test_redeem_confirm_using_verification_code(self):
        """When an redeem link is rendered, call the redis key to get the UAA invite link"""

        self.redis.get.return_value = b'inviteLink'

        rv = self.c.get('/redeem-invite?verification_code=some_verification_code')
        redeem_link = 'http://localhost:5000/redeem-invite?verification_code=some_verification_code'

        self.assertEqual(rv.status_code, 200)
        self.render_template.assert_called_with('redeem-confirm.html', redeem_link=redeem_link)

    def test_redeem_uaainvite_using_verification_code(self):
        """Render UAA link after redeem link is clicked"""

        self.redis.get.return_value = b'http://idp.example.com/inviteLink'

        rv = self.c.post('/redeem-invite?verification_code=some_verification_code', data={'_csrf_token': 'bar'})
        self.assertEqual(rv.status_code, 302)
        self.assertEqual(rv.location, 'http://idp.example.com/inviteLink')

    def test_redeem_without_redis(self):
        """When an redeem endpoint is hit without redis, it should fail"""

        self.redis.ping.side_effect = Exception()

        rv = self.c.get('/redeem-invite?verification_code=some_verification_code')
        self.assertEqual(rv.status_code, 500)
        self.render_template.assert_called_with('error/internal.html')
