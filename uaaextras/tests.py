from datetime import datetime, timedelta
from contextlib import contextmanager
import json
import ipdb
import random
import string
from posixpath import join as urljoin
import unittest

import flask
from flask import appcontext_pushed
from mock import Mock, patch
from requests.auth import HTTPBasicAuth

from uaaextras.webapp import create_app, send_email, str_to_bool, CONFIG_KEYS, do_expiring_pw_notifications
from uaaextras.clients import UAAError, UAAClient

app = create_app({'UAA_CLIENT_ID': 'client-id', 'UAA_CLIENT_SECRET': 'client-secret',
                  'PW_EXPIRES_DAYS': 30, 'PW_EXPIRATION_WARN_DAYS': 5})


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

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.r', None)
    def test_notify_expiring_no_redis_connection(self, uaac):
        """When there is no redis connection, don't even connect to UAA"""

        do_expiring_pw_notifications(app, 'http://example.org/change')
        uaac().client_users.assert_not_called()

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.datetime')
    @patch('uaaextras.webapp.divmod')
    @patch('uaaextras.webapp.r')
    def test_notify_expiring_uaa_no_results(self, redis_conn, m_divmod, m_datetime, uaac):
        """When UAA returns no results, make sure we don't do any time checking or paging"""

        redis_conn.get.return_value = None

        uaac().client_users.return_value = {'totalResults': 0, 'itemsPerPage': 100, 'resources': []}

        do_expiring_pw_notifications(app, 'http://example.org/change')
        m_datetime.strptime.assert_not_called()
        m_divmod.assert_not_called()

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.divmod')
    @patch('uaaextras.webapp.r')
    def test_notify_expiring_uaa_has_results_not_enough_to_page(self, redis_conn, m_divmod, uaac):
        """When When UAA does return results, do email, but not paging because not enough results"""

        redis_conn.get.return_value = None

        passwordLastModified = (datetime.now() - timedelta(days=31)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        val = {
            'totalResults': 1,
            'itemsPerPage': 1,
            'resources': [
                {
                    'userName': 'test@example.org',
                    'passwordLastModified': passwordLastModified
                }
            ]
        }
        uaac().client_users.return_value = val

        do_expiring_pw_notifications(app, 'http://example.org/change')
        assert uaac().client_users.called
        assert uaac().client_users.call_count == 1
        m_divmod.assert_not_called()

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.r')
    def test_notify_expiring_uaa_has_results_and_handles_more_pages(self, redis_conn, uaac):
        """When When UAA does return results, do email, and paging"""

        redis_conn.get.return_value = None

        passwordLastModified = (datetime.now() - timedelta(days=31)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # This should give us 3 pages of results
        val = {
            'totalResults': 5,
            'itemsPerPage': 2,
            'resources': [
                {
                    'userName': 'test1@example.org',
                    'passwordLastModified': passwordLastModified
                },
                {
                    'userName': 'test2@example.org',
                    'passwordLastModified': passwordLastModified
                },
                {
                    'userName': 'test3@example.org',
                    'passwordLastModified': passwordLastModified
                },
                {
                    'userName': 'test4@example.org',
                    'passwordLastModified': passwordLastModified
                },
                {
                    'userName': 'test5@example.org',
                    'passwordLastModified': passwordLastModified
                }
            ]
        }
        uaac().client_users.return_value = val

        do_expiring_pw_notifications(app, 'http://example.org/change')
        assert uaac().client_users.called
        assert uaac().client_users.call_count == 3

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.send_email')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    def test_notifies_users_when_password_is_not_yet_expired(self, redis_conn, render_template, send_email, uaac):
        """When user password expires within warning days, notify"""
        redis_conn.get.return_value = None

        passwordLastModified = (datetime.now() - timedelta(days=26)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        val = {
            'totalResults': 1,
            'itemsPerPage': 1,
            'resources': [
                {
                    'userName': 'test@example.org',
                    'passwordLastModified': passwordLastModified
                }
            ]
        }
        uaac().client_users.return_value = val

        do_expiring_pw_notifications(app, 'http://example.org/change')
        assert render_template.called
        assert render_template.call_count == 2
        assert send_email.called
        assert send_email.call_count == 1

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.send_email')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    def test_does_not_notify_after_password_expired(self, redis_conn, render_template, send_email, uaac):
        """When user password has already expired, do not notify"""
        redis_conn.get.return_value = None

        passwordLastModified = (datetime.now() - timedelta(days=31)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        val = {
            'totalResults': 1,
            'itemsPerPage': 1,
            'resources': [
                {
                    'userName': 'test@example.org',
                    'passwordLastModified': passwordLastModified
                }
            ]
        }
        uaac().client_users.return_value = val

        do_expiring_pw_notifications(app, 'http://example.org/change')

        render_template.assert_not_called()

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.r')
    def test_notify_expiring_only_runs_once_a_day(self, redis_conn, uaac):
        """When notifcations have already run once in a day, don't run again"""

        redis_conn.get.return_value = True
        do_expiring_pw_notifications(app, 'http://example.org/change')
        redis_conn.setex.assert_not_called()

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
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 500
            print(uaac.invite_users())

            render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.smtplib')
    @patch('uaaextras.webapp.send_email')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    @patch('uaaextras.webapp.uuid')
    @patch('uaaextras.webapp.UAA_INVITE_EXPIRATION_IN_SECONDS')
    def test_invite_good(self, UAA_INVITE_EXPIRATION_IN_SECONDS, uuid, redis_conn, render_template, send_email, smtplib, uaac):
        """When an invite is sucessfully sent, the invite_sent template is displayed"""

        uaac().invite_users.return_value = {'failed_invites': [], 'new_invites': [{'inviteLink': 'testLink', 'some': 'invite'}]}
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            redis_conn.setex.assert_called_with(
                uuid.uuid4().hex,
                UAA_INVITE_EXPIRATION_IN_SECONDS,
                'testLink'
            )

            render_template.assert_called_with('invite_sent.html')

        assert send_email.called
        assert send_email.call_count == 1

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.render_template')
    def test_invite_user_exists(self, render_template, flash, uaac):
        """When an user already exists during invite process, the invite.html template is displayed"""

        uaac().does_origin_user_exist.return_value = True

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/invite', data={'email': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('invite.html')
            flash.assert_called_once()

    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.FED_DOTGOV_LIST', [['GSA.GOV']])
    def test_get_signup(self, render_template):
        """When a GET request is made to /signup, the signup.html template is displayed"""

        render_template.return_value = 'template output'

        with app.test_client() as c:

            rv = c.get('/signup')
            assert rv.status_code == 200
            render_template.assert_called_with('signup.html')

    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.FED_DOTGOV_LIST', [['GSA.GOV']])
    def test_signup_bad_email(self, render_template, flash):
        """When an email is blank or invalid, or not federal gov, the error is flashed to the user"""

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/signup', data={'email': '', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('signup.html')
            flash.assert_called_once()

        flash.reset_mock()
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/signup', data={'email': 'not an email', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('signup.html')
            flash.assert_called_once()

        flash.reset_mock()
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/signup', data={'email': 'foo@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('signup.html')
            flash.assert_called_once()

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.FED_DOTGOV_LIST', [['GSA.GOV']])
    def test_signup_error(self, render_template, uaac):
        """When an error occurs during the signup process, the error/internal.html template is displayed"""

        uaac().client_invite_users.return_value = {'failed_invites': [{'fail': 'here'}], 'new_invites': []}
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/signup', data={'email': 'cloud-gov-notifications@gsa.gov', '_csrf_token': 'bar'})
            assert rv.status_code == 500
            print(uaac.client_invite_users())

            render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.send_email')
    @patch('uaaextras.webapp.smtplib')
    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    @patch('uaaextras.webapp.uuid')
    @patch('uaaextras.webapp.UAA_INVITE_EXPIRATION_IN_SECONDS')
    @patch('uaaextras.webapp.FED_DOTGOV_LIST', [['GSA.GOV']])
    def test_signup_good(self, UAA_INVITE_EXPIRATION_IN_SECONDS, uuid, redis_conn, render_template, uaac, smtp, send_email):
        """When an signup is sucessfully sent, the signup_invite_sent template is displayed"""

        uaac().client_invite_users.return_value = {'failed_invites': [], 'new_invites': [{'inviteLink': 'testLink', 'some': 'invite'}]}
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'foo'

            rv = c.post('/signup', data={'email': 'cloud-gov-notifications@gsa.gov', '_csrf_token': 'foo'})
            
            assert rv.status_code == 200
            render_template.assert_called_with('signup_invite_sent.html')

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/signup', data={'email': 'example@mail.mil', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('signup_invite_sent.html')

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'baz'

            rv = c.post('/signup', data={'email': 'example@fs.fed.us', '_csrf_token': 'baz'})
            assert rv.status_code == 200
            render_template.assert_called_with('signup_invite_sent.html')

    @patch('uaaextras.webapp.UAAClient')
    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.FED_DOTGOV_LIST', [['GSA.GOV']])
    def test_signup_user_exists(self, render_template, flash, uaac):
        """When an user already exists during signup process, the signup.html template is displayed"""

        uaac().does_origin_user_exist.return_value = True

        render_template.return_value = 'template content'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/signup', data={'email': 'cloud-gov-notifications@gsa.gov', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            render_template.assert_called_with('signup.html')
            flash.assert_called_once()

    @patch('uaaextras.webapp.session')
    def test_logout_good(self, session):
        """The session is cleared when logging out"""

        with app.test_request_context('/logout'):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess['UAA_TOKEN'] = 'foo'

                rv = c.get('/logout')
                assert rv.status_code == 302
                assert rv.location == 'http://localhost:5000/'
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

    @patch('uaaextras.webapp.render_template')
    def test_get_change_password(self, render_template):
        """ When a GET request is made to /change-password,
            the change_password.html template is displayed
        """
        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'

            rv = c.get('/change-password')
            assert rv.status_code == 200
            render_template.assert_called_with('change_password.html')

    @patch('uaaextras.webapp.redirect')
    @patch('uaaextras.webapp.UAAClient')
    def test_first_login_with_idp_provider(self, uaac, redirect):
        """ When a GET request is made to /first-login,
            the user is redirected to IDP_PROVIDER_URL with an origin of 'uaa'
        """
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'

            user = {
                'origin': 'uaa',
                'userName': 'testUser'
            }

            uaac().decode_access_token.return_value = {
                'user_id': 'example'
            }
            uaac().get_user.return_value = user

            c.get('/first-login')
            assert 'externalId' in user
            assert user['origin'] == app.config['IDP_PROVIDER_ORIGIN']
            redirect.assert_called_with(app.config['IDP_PROVIDER_URL'])

    @patch('uaaextras.webapp.redirect')
    @patch('uaaextras.webapp.UAAClient')
    def test_first_login_with_uaa_provider(self, uaac, redirect):
        """ When a GET request is made to /first-login,
            the user is redirected to UAA_BASE_URL with an origin other
            than 'uaa'.
        """
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['UAA_TOKEN'] = 'foo'

            user = {
                'origin': 'example',
                'userName': 'testUser'
            }

            uaac().decode_access_token.return_value = {
                'user_id': 'example'
            }
            uaac().get_user.return_value = user

            c.get('/first-login')
            redirect.assert_called_with(app.config['UAA_BASE_URL'])

    @patch('uaaextras.webapp.render_template')
    def test_get_forgot_password(self, render_template):
        """ When a GET request is made to /forgot-password,
            the forgot_password.html template is displayed
        """
        render_template.return_value = 'template output'

        with app.test_client() as c:

            rv = c.get('/forgot-password')
            assert rv.status_code == 200
            render_template.assert_called_with('forgot_password.html')

    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r', None)
    def test_no_redis_forgot_password(self, render_template):
        """ When submitting an email and redis is down, server responsds 500
        """

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/forgot-password', data={'email_address': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 500
            render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    @patch('uaaextras.webapp.smtplib')
    @patch('uaaextras.webapp.uuid')
    @patch('uaaextras.webapp.FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS')
    def test_setting_email_in_redis(
        self,
        FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS,
        uuid,
        smtplib,
        redis_conn,
        render_template
    ):
        """ When submitting an email, the email and token are set in the Redis DB
        """

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post('/forgot-password', data={'email_address': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 200
            redis_conn.setex.assert_called_with(
                'test@example.com',
                FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS,
                uuid.uuid4().hex
            )
            render_template.assert_called_with(
                'forgot_password.html',
                email_sent=True,
                email='test@example.com'
            )

    @patch('uaaextras.webapp.render_template')
    def test_get_reset_password(self, render_template):
        """ When a GET request is made to /reset-password,
            and the validation code is passed in correctly
            the reset_password.html template is displayed
        """
        render_template.return_value = 'template output'

        with app.test_client() as c:

            rv = c.get('/reset-password?validation=foo')
            assert rv.status_code == 200
            render_template.assert_called_with('reset_password.html', validation_code='foo')

    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.render_template')
    def test_get_reset_password_bad_code(self, render_template, flash):
        """ When a GET request is made to /reset-password,
            and the validation code is not passed in correctly
            the reset_password.html template is displayed
            and error message is put in flash
        """
        render_template.return_value = 'template output'

        with app.test_client() as c:

            rv = c.get('/reset-password')
            assert rv.status_code == 200
            render_template.assert_called_with('reset_password.html', validation_code=None)
            flash.assert_called_once()

    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r', None)
    def test_no_redis_reset_password(self, render_template):
        """ When submitting an email and redis is down, server responsds 500
        """

        render_template.return_value = 'template output'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_validation_code'] = 'bar'
                sess['_csrf_token'] = 'bar'

            rv = c.post('/reset-password', data={'email_address': 'test@example.com', '_csrf_token': 'bar'})
            assert rv.status_code == 500
            render_template.assert_called_with('error/internal.html')

    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    @patch('uaaextras.webapp.generate_temporary_password')
    @patch('uaaextras.webapp.UAAClient')
    def test_render_temporary_password(
        self,
        uaac,
        generate_temporary_password,
        redis_conn,
        render_template
    ):
        """ When submitting an email and a valid token, we should render a temporary password.
        """

        render_template.return_value = 'template output'
        redis_conn.get.return_value = b'example'
        uaac().set_temporary_password.return_value = generate_temporary_password()

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post(
                '/reset-password',
                data={
                    'email_address': 'test@example.com',
                    '_validation_code': 'example',
                    '_csrf_token': 'bar'
                }
            )
            assert rv.status_code == 200
            redis_conn.get.assert_called_with('test@example.com')
            redis_conn.delete.assert_called_with('test@example.com')
            render_template.assert_called_with('reset_password.html', password=generate_temporary_password())

    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.flash')
    @patch('uaaextras.webapp.r')
    def test_fail_to_render_temporary_password(
        self,
        redis_conn,
        flash,
        render_template
    ):
        """ When submitting an email without a valid token, I should see a flash error message.
        """

        render_template.return_value = 'template output'
        redis_conn.get.return_value = b'example'

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['_csrf_token'] = 'bar'

            rv = c.post(
                '/reset-password',
                data={
                    'email_address': 'test@example.com',
                    '_validation_code': 'not-example',
                    '_csrf_token': 'bar'
                }
            )
            assert rv.status_code == 200
            redis_conn.get.assert_called_with('test@example.com')
            render_template.assert_called_with('reset_password.html')
            flash.assert_called_once()


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


    @patch('uaaextras.webapp.render_template')
    def test_redeem_no_verification_code(self, render_template):
        """When an redeem link is rendered, fail if there is no matching verification code"""

        render_template.return_value = 'some value'
        with app.test_client() as c:

            rv = c.get('/redeem-invite')

            assert rv.status_code == 401

            render_template.assert_called_with('error/token_validation.html')
    
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r')
    def test_redeem_using_verification_code(self, redis_conn, render_template):
        """When an redeem link is rendered, call the redis key to get the UAA invite link"""

        inviteLink = b'inviteLink'
        render_template.return_value = 'some value'
        redis_conn.get.return_value = inviteLink
        
        with app.test_client() as c:

            rv = c.get('/redeem-invite?verification_code=some_verification_code')

            assert rv.status_code == 200

            render_template.assert_called_with('redeem.html', invite=bytes.decode(inviteLink) )   
    
    @patch('uaaextras.webapp.render_template')
    @patch('uaaextras.webapp.r', None)
    def test_redeem_using_verification_code(self, render_template):
        """When an redeem link is rendered, call the redis key to get the UAA invite link"""

        render_template.return_value = 'some value'
        
        with app.test_client() as c:

            rv = c.get('/redeem-invite?verification_code=some_verification_code')

            assert rv.status_code == 500

            render_template.assert_called_with('error/internal.html' )    

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
        m.assert_called_with('/Users', 'GET', params={'startIndex': 1}, headers={})

        uaac.users(start=2)
        m.assert_called_with('/Users', 'GET', params={'startIndex': 2}, headers={})

        uaac.users(list_filter='test filter')
        m.assert_called_with('/Users', 'GET',
                             params={'filter': 'test filter', 'startIndex': 1}, headers={})

        uaac.users(token='FOO')
        m.assert_called_with('/Users', 'GET', params={'startIndex': 1},
                             headers={'Authorization': 'Bearer FOO'})

        uaac.users('test filter', 'FOO', 9)
        m.assert_called_with('/Users', 'GET', params={'filter': 'test filter', 'startIndex': 9},
                             headers={'Authorization': 'Bearer FOO'})

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

        email = 'foo@example.com'
        redirect_uri = 'http://www.example.com'

        uaac.invite_users(email, redirect_uri)

        m.assert_called_with(
            '/invite_users',
            'POST',
            body={'emails': [email]},
            headers={},
            params={'redirect_uri': redirect_uri}
        )

    def test_users_with_token(self):
        """invite_users() makes a PUT request to /invite_users<id>"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        email = 'foo@example.com'
        redirect_uri = 'http://www.example.com'

        uaac.invite_users(email, redirect_uri, token="foobar")

        m.assert_called_with(
            '/invite_users',
            'POST',
            body={'emails': [email]},
            headers={'Authorization': 'Bearer foobar'},
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

    def test_get_client_token(self):
        """_get_client_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac._get_client_token('bar', 'baz')

        args, kwargs = m.call_args

        assert args == ('/oauth/token', 'POST')

        assert kwargs['params'] == {
            'grant_type': 'client_credentials',
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

    def test_change_password(self):
        """change_password() makes a PUT request to /Users/<id>/password"""

        uaac = UAAClient('http://example.com', 'foo', False)
        m = Mock()
        uaac._request = m

        uaac.change_password('foo', 'bar', 'baz')

        m.assert_called_with(
            '/Users/foo/password',
            'PUT',
            body={
                'oldPassword': 'bar',
                'password': 'baz'
            }
        )
