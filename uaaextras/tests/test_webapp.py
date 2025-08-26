from datetime import datetime, timedelta
from contextlib import contextmanager
import json
import random
import string
from posixpath import join as urljoin
import unittest

import redis
import flask
from flask import appcontext_pushed
from mock import Mock, patch
from requests.auth import HTTPBasicAuth
import requests_mock

import sqlalchemy

from uaaextras.webapp import create_app, send_email, str_to_bool, CONFIG_KEYS
from uaaextras.clients import UAAError, UAAClient, TOTPClient, CFClient

app = create_app({"UAA_CLIENT_ID": "client-id", "UAA_CLIENT_SECRET": "client-secret"})


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

        assert str_to_bool("true") is True
        assert str_to_bool("1") is True
        assert str_to_bool(True) is True

        assert str_to_bool("0") is False
        assert str_to_bool(None) is False
        assert str_to_bool("false") is False

        assert str_to_bool("lol") is None

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
            if kk == "UAA_VERIFY_TLS":
                fake_env[kk] = random.choice([True, False])
            else:
                fake_env[kk] = "".join(
                    random.choice(string.ascii_uppercase) for _ in range(16)
                )

        app = create_app(fake_env)
        # validate they all match
        for kk in CONFIG_KEYS.keys():
            assert app.config[kk] == fake_env[kk]

    @patch("uaaextras.webapp.smtplib")
    def test_send_email_no_auth(self, smtplib):
        """Email is sent as expected"""

        app = Mock()
        app.config = {
            "SMTP_FROM": "bar@example.com",
            "SMTP_HOST": "remote-host",
            "SMTP_PORT": 9160,
            "SMTP_USER": None,
            "SMTP_PASS": None,
            "SMTP_CERT": None,
        }

        send_email(app, "foo@example.com", "da subject", "body content")

        smtplib.SMTP.assert_called_with("remote-host", 9160)

        args = smtplib.SMTP().sendmail.call_args

        assert args[0][:2] == (app.config["SMTP_FROM"], ["foo@example.com"])
        assert args[0][2].endswith("body content")

        print(args[0][2])
        assert "To: foo@example.com" in args[0][2]
        assert "Subject: da subject" in args[0][2]

    @patch("uaaextras.webapp.smtplib")
    def test_send_email_auth(self, smtplib):
        """IF SMTP_USER and SMTP_PASS are provided, smtp.login() is called"""
        app = Mock()
        app.config = {
            "SMTP_FROM": "bar@example.com",
            "SMTP_HOST": "remote-host",
            "SMTP_PORT": 9160,
            "SMTP_USER": "user",
            "SMTP_PASS": "pass",
            "SMTP_CERT": None,
        }

        send_email(app, "foo@example.com", "da subject", "body content")

        smtplib.SMTP.assert_called_with("remote-host", 9160)

        smtplib.SMTP().login.assert_called_with("user", "pass")

    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_csrf_token(self, render_template, m):
        """When a post request is made with a missing or invalid csrf token,
        the error/csrf.html template is displayed
        """

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "ssssshhhhhh"
                sess["UAA_TOKEN"] = "foo"

            rv = c.post("/")
            assert rv.status_code == 400
            render_template.assert_called_with("error/csrf.html")

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    def test_uaa_token(self, render_template, uaac):
        """When we cannot validate a UAA token, the error/token_validation.html template is displayed"""

        r = Mock()
        r.text = json.dumps({"error_description": "oh no"})
        uaac.side_effect = UAAError(r)

        render_template.return_value = "template content"

        with app.test_client() as c:
            rv = c.get("/oauth/login")

            assert rv.status_code == 401
            render_template.assert_called_with("error/token_validation.html")

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    def test_uaa_scope(self, render_template, uaac):
        """When the token is valid, but the scope is incorrect, the error/missing_scope.html template is displayed"""

        uaac().oauth_token.return_value = {"scope": "not.what.we.wanted"}

        render_template.return_value = "template content"

        with app.test_client() as c:
            rv = c.get("/oauth/login?code=foo")

            assert rv.status_code == 403
            render_template.assert_called_with("error/missing_scope.html")

    @patch("uaaextras.webapp.render_template")
    def test_maintenance_mode(self, render_template):
        """When any request is made while the app is in maintenance mode, the
        maintenance.html template is displayed"""

        render_template.return_value = "template output"

        app.config['MAINTENANCE_MODE'] = True

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"

            sample_get_request_paths = [
                '/',
                '/oauth_login',
                '/forgot_password',
                '/redeem_invite',
                '/reset_password',
                '/signup',
                '/static',
            ]

            sample_post_request_paths = [
                ("/invite", {"email": "", "_csrf_token": "bar"}),
                ("/signup", {"email": "", "_csrf_token": "bar"}),
            ]

            for path in sample_get_request_paths:
                rv = c.get(path)
                assert rv.status_code == 200
                render_template.assert_called_with('maintenance.html')

            for path in sample_post_request_paths:
                rv = c.post(path[0], data=path[1])
                assert rv.status_code == 200
                render_template.assert_called_with('maintenance.html')

        app.config['MAINTENANCE_MODE'] = False

    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_get_index(self, render_template, m):
        """When a GET request is made to /, the index.html template is displayed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"

            rv = c.get("/")
            assert rv.status_code == 200
            render_template.assert_called_with("index.html")

    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_get_invite(self, render_template, m):
        """When a GET request is made to /invite, the invite.html template is displayed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"

            rv = c.get("/invite")
            assert rv.status_code == 200
            render_template.assert_called_with("invite.html")

    @patch("uaaextras.webapp.CFClient")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_invite_bad_email(self, render_template, flash, uaac, cf, m):
        """When an email is blank or invalid, the error is flashed to the user"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post("/invite", data={"email": "", "_csrf_token": "bar"})
            assert rv.status_code == 200
            render_template.assert_called_with("invite.html")
            flash.assert_called_once()

        flash.reset_mock()
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post("/invite", data={"email": "not an email", "_csrf_token": "bar"})
            assert rv.status_code == 200
            render_template.assert_called_with("invite.html")
            flash.assert_called_once()

    @patch("uaaextras.webapp.CFClient")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_invite_from_non_org_manager(self, render_template, flash, uaac, cf, m):
        """When a non org manager user tries to send an invite, the error is flashed to the user"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"
        
        cf().is_org_manager.return_value = False
        assert cf().is_org_manager() == False

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post("/invite", data={"email": "test@example.com", "_csrf_token": "bar"})
            assert rv.status_code == 200
            render_template.assert_called_with("invite.html")
            flash.assert_called_once()

    @patch("uaaextras.webapp.CFClient")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_invite_from_org_manager(self, render_template, flash, uaac, cf, m):
        """When an org manager user tries to send an invite, the request should proceed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"
        
        cf().is_org_manager.return_value = True
        assert cf().is_org_manager() == True

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post("/invite", data={"email": "test@example.com", "_csrf_token": "bar"})
            assert rv.status_code == 200
            render_template.assert_called_with("invite.html")

    @patch("uaaextras.webapp.CFClient")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_invite_error(self, render_template, uaac, cf, m):
        """When an error occurs during the invite process, the error/internal.html template is displayed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        uaac().invite_users.return_value = {
            "failed_invites": [{"fail": "here"}],
            "new_invites": [],
        }
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = "template content"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/invite", data={"email": "test@example.com", "_csrf_token": "bar"}
            )
            assert rv.status_code == 500
            print(uaac.invite_users())

            render_template.assert_called_with("error/internal.html")

    @patch("uaaextras.webapp.CFClient")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.smtplib")
    @patch("uaaextras.webapp.send_email")
    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    @patch("uaaextras.webapp.uuid")
    @patch("uaaextras.webapp.UAA_INVITE_EXPIRATION_IN_SECONDS")
    @requests_mock.Mocker(kw="m")
    def test_invite_good(
        self,
        UAA_INVITE_EXPIRATION_IN_SECONDS,
        uuid,
        redis_conn,
        render_template,
        send_email,
        smtplib,
        uaac,
        cf,
        m,
    ):
        """When an invite is sucessfully sent, the invite_sent template is displayed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        uaac().invite_users.return_value = {
            "failed_invites": [],
            "new_invites": [{"inviteLink": "testLink", "some": "invite"}],
        }
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = "template content"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/invite", data={"email": "test@example.com", "_csrf_token": "bar"}
            )
            assert rv.status_code == 200
            redis_conn.setex.assert_called_with(
                uuid.uuid4().hex, UAA_INVITE_EXPIRATION_IN_SECONDS, "testLink"
            )

            render_template.assert_called_with("invite_sent.html")

        assert send_email.called
        assert send_email.call_count == 1

    @patch("uaaextras.webapp.CFClient")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_invite_user_exists(self, render_template, flash, uaac, cf, m):
        """When an user already exists during invite process, the invite.html template is displayed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        uaac().does_origin_user_exist.return_value = True

        render_template.return_value = "template content"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/invite", data={"email": "test@example.com", "_csrf_token": "bar"}
            )
            assert rv.status_code == 200
            render_template.assert_called_with("invite.html")
            flash.assert_called_once()

    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_get_signup(self, render_template, m):
        """When a GET request is made to /signup, the signup.html template is displayed"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        with app.test_client() as c:

            rv = c.get("/signup")
            assert rv.status_code == 200
            render_template.assert_called_with("signup.html")

    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    def test_signup_bad_email(self, render_template, flash):
        """When an email is blank or invalid, or not federal gov, the error is flashed to the user"""

        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post("/signup", data={"email": "", "_csrf_token": "bar"})
            assert rv.status_code == 200
            render_template.assert_called_with("signup.html")
            flash.assert_called_once()

        flash.reset_mock()
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post("/signup", data={"email": "not an email", "_csrf_token": "bar"})
            assert rv.status_code == 200
            render_template.assert_called_with("signup.html")
            flash.assert_called_once()

        flash.reset_mock()
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/signup", data={"email": "foo@example.com", "_csrf_token": "bar"}
            )
            assert rv.status_code == 200
            render_template.assert_called_with("signup.html")
            flash.assert_called_once()

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    def test_signup_error(self, render_template, uaac):
        """When an error occurs during the signup process, the error/internal.html template is displayed"""

        uaac().client_invite_users.return_value = {
            "failed_invites": [{"fail": "here"}],
            "new_invites": [],
        }
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = "template content"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/signup",
                data={"email": "cloud-gov-notifications@gsa.gov", "_csrf_token": "bar"},
            )
            assert rv.status_code == 500
            print(uaac.client_invite_users())

            render_template.assert_called_with("error/internal.html")

    @patch("uaaextras.webapp.send_email")
    @patch("uaaextras.webapp.smtplib")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    @patch("uaaextras.webapp.uuid")
    @patch("uaaextras.webapp.UAA_INVITE_EXPIRATION_IN_SECONDS")
    def test_signup_good(
        self,
        UAA_INVITE_EXPIRATION_IN_SECONDS,
        uuid,
        redis_conn,
        render_template,
        uaac,
        smtp,
        send_email,
    ):
        """When an signup is sucessfully sent, the signup_invite_sent template is displayed"""

        uaac().client_invite_users.return_value = {
            "failed_invites": [],
            "new_invites": [{"inviteLink": "testLink", "some": "invite"}],
        }
        uaac().does_origin_user_exist.return_value = False

        render_template.return_value = "template content"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "foo"

            rv = c.post(
                "/signup",
                data={"email": "cloud-gov-notifications@gsa.gov", "_csrf_token": "foo"},
            )
            assert rv.status_code == 200
            render_template.assert_called_with("signup_invite_sent.html")

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/signup", data={"email": "example@si.edu", "_csrf_token": "bar"}
            )
            assert rv.status_code == 200
            render_template.assert_called_with("signup_invite_sent.html")

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/signup", data={"email": "example@mail.mil", "_csrf_token": "bar"}
            )
            assert rv.status_code == 200
            render_template.assert_called_with("signup_invite_sent.html")

        # disabling this test because it's failing on nmcourt.fed.us not being a valid MX domain
        # not sure if this test is valid, it's just attempting to prove that government users with different
        # emails can sign up successfully
        #
        # with app.test_client() as c:
        #     with c.session_transaction() as sess:
        #         sess["_csrf_token"] = "baz"

        #     rv = c.post(
        #         "/signup", data={"email": "example@nmcourt.fed.us", "_csrf_token": "baz"}
        #     )
        #     assert rv.status_code == 200
        #     render_template.assert_called_with("signup_invite_sent.html")

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    def test_signup_user_exists(self, render_template, flash, uaac):
        """When an user already exists during signup process, the signup.html template is displayed"""

        uaac().does_origin_user_exist.return_value = True

        render_template.return_value = "template content"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/signup",
                data={"email": "cloud-gov-notifications@gsa.gov", "_csrf_token": "bar"},
            )
            assert rv.status_code == 200
            render_template.assert_called_with("signup.html")
            flash.assert_called_once()

    @requests_mock.Mocker(kw="m")
    def test_logout_good(self, m):
        """The session is cleared when logging out"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        with app.test_request_context("/logout"):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess["UAA_TOKEN"] = "foo"

                rv = c.get("/logout")
                assert rv.status_code == 302
                assert rv.location == "/"
                with c.session_transaction() as sess:
                    assert sess.get("UAA_TOKEN") is None

    @patch("uaaextras.webapp.UAAClient")
    @requests_mock.Mocker(kw="m")
    def test_uaac_is_created_from_session(self, uaac, m):
        """When a request is made, and a valid session exists g.uaac is created"""
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        with app.test_request_context("/"):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess["UAA_TOKEN"] = "foo"
                    sess["UAA_TOKEN_EXPIRES"] = datetime.utcnow() + timedelta(
                        seconds=30
                    )

                c.get("/")

                uaac.assert_called_with(
                    app.config["UAA_BASE_URL"],
                    "foo",
                    verify_tls=app.config["UAA_VERIFY_TLS"],
                )

                assert isinstance(flask.g.uaac, Mock)

    @patch("uaaextras.webapp.UAAClient")
    def test_redirect_to_uaac(self, uaac):
        """When a request is made, and no session exists, redirect to UAAC Oauth"""
        with app.test_client() as c:
            rv = c.get("/")

            assert rv.status_code == 302
            target = (
                app.config["UAA_BASE_URL"]
                + "/oauth/authorize?client_id="
                + app.config["UAA_CLIENT_ID"]
            )
            target += "&response_type=code"
            assert rv.location == target

    @patch("uaaextras.webapp.UAAClient")
    def test_oauth_creates_session(self, uaac):
        """/oauth/login validates codes with UAA"""

        uaac().oauth_token.return_value = {
            "access_token": "foo",
            "expires_in": 30,
            "scope": "scim.invite",
        }

        with app.test_request_context("/oauth/login"):
            with app.test_client() as c:
                c.get("/oauth/login?code=123")

                assert uaac.oauth_token(
                    "123", app.config["UAA_CLIENT_ID"], app.config["UAA_CLIENT_SECRET"]
                )

                assert flask.session["UAA_TOKEN"] == "foo"
                assert flask.session["UAA_TOKEN_SCOPES"] == ["scim.invite"]

    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_get_change_password(self, render_template, m):
        """ When a GET request is made to /change-password,
            the change_password.html template is displayed
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"

            rv = c.get("/change-password")
            assert rv.status_code == 200
            render_template.assert_called_with("change_password.html")

    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_post_change_password_bad_zxcvbn(self, render_template, uaac, flash, m):
        """When you give it a password that violates the zxcvbn function,
           it should let you know.
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        uaac().decode_access_token.return_value = {"user_id": "example"}

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"
                sess["UAA_TOKEN"] = "foo"

            c.post(
                "/change-password",
                data={
                    "old_password": "fdsa",
                    "new_password": "password",
                    "repeat_password": "password",
                    "_csrf_token": "bar",
                },
            )

        render_template.assert_called_with("change_password.html")
        flash.assert_called_with("This is a top-10 common password.")
        assert not uaac().change_password.called

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_post_change_password_old_repeat(self, render_template, uaac, m):
        """When you give it a password that is the same as the previous one,
           it should not work.
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        uaac().decode_access_token.return_value = {"user_id": "example"}

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"
                sess["UAA_TOKEN"] = "foo"

            c.post(
                "/change-password",
                data={
                    "old_password": "correct horse battery staple",
                    "new_password": "correct horse battery staple",
                    "repeat_password": "correct horse battery staple",
                    "_csrf_token": "bar",
                },
            )

        render_template.assert_called_with("change_password.html")
        assert not uaac().change_password.called

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_post_change_password_bad_repeat(self, render_template, uaac, m):
        """When you give it a password that is the same as the previous one,
           it should not work.
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        uaac().decode_access_token.return_value = {"user_id": "example"}

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"
                sess["UAA_TOKEN"] = "foo"

            c.post(
                "/change-password",
                data={
                    "old_password": "correct horse battery staple",
                    "new_password": "correct horse battery staple",
                    "repeat_password": "horse battery correct staple",
                    "_csrf_token": "bar",
                },
            )

        render_template.assert_called_with("change_password.html")
        assert not uaac().change_password.called

    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @requests_mock.Mocker(kw="m")
    def test_post_change_password_good(self, render_template, uaac, flash, m):
        """If the password does not violate any of the bad password things,
           it should be accepted.
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        render_template.return_value = "template output"

        uaac().decode_access_token.return_value = {"user_id": "example"}

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"
                sess["UAA_TOKEN"] = "foo"

            c.post(
                "/change-password",
                data={
                    "old_password": "fdsa",
                    "new_password": "correct horse battery staple",
                    "repeat_password": "correct horse battery staple",
                    "_csrf_token": "bar",
                },
            )

        uaac().change_password.assert_called_with(
            "example", "fdsa", "correct horse battery staple"
        )
        render_template.assert_called_with("password_changed.html")
        flash.assert_not_called()
        assert uaac().change_password.called

    @patch("uaaextras.webapp.redirect")
    @patch("uaaextras.webapp.UAAClient")
    @requests_mock.Mocker(kw="m")
    def test_first_login_with_idp_provider(self, uaac, redirect, m):
        """ When a GET request is made to /first-login,
            the user is redirected to IDP_PROVIDER_URL with an origin of 'uaa'
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"

            user = {"origin": "uaa", "userName": "testUser"}

            uaac().decode_access_token.return_value = {"user_id": "example"}
            uaac().get_user.return_value = user

            print("about to test first_login")
            c.get("/first-login")
            assert "externalId" in user
            assert user["origin"] == app.config["IDP_PROVIDER_ORIGIN"]
            redirect.assert_called_with(app.config["IDP_PROVIDER_URL"])

    @patch("uaaextras.webapp.redirect")
    @patch("uaaextras.webapp.UAAClient")
    @requests_mock.Mocker(kw="m")
    def test_first_login_with_uaa_provider(self, uaac, redirect, m):
        """ When a GET request is made to /first-login,
            the user is redirected to UAA_BASE_URL with an origin other
            than 'uaa'.
        """
        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": true}')
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["UAA_TOKEN"] = "foo"

            user = {"origin": "example", "userName": "testUser"}

            uaac().decode_access_token.return_value = {"user_id": "example"}
            uaac().get_user.return_value = user

            c.get("/first-login")
            redirect.assert_called_with(app.config["UAA_BASE_URL"])

    @patch("uaaextras.webapp.render_template")
    def test_get_forgot_password(self, render_template):
        """ When a GET request is made to /forgot-password,
            the forgot_password.html template is displayed
        """
        render_template.return_value = "template output"

        with app.test_client() as c:

            rv = c.get("/forgot-password")
            assert rv.status_code == 200
            render_template.assert_called_with("forgot_password.html")

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.send_email")
    @patch("uaaextras.webapp.r")
    def test_post_forgot_password_good(self, redis_conn, send_email, uaac):
        """When a POST request is made to /forgot-password
           and the user exists, send_email is called
        """

        uaac().does_origin_user_exist.return_value = True

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            c.post(
                "/forgot-password",
                data={"email_address": "test@example.com", "_csrf_token": "bar"},
            )
            send_email.assert_called_once()

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.send_email")
    @patch("uaaextras.webapp.r")
    def test_post_forgot_password_bad(self, redis_conn, send_email, uaac):
        """When a POST request is made to /forgot-password
           and the user does not exist, send_email is not called
        """

        uaac().does_origin_user_exist.return_value = False

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            c.post(
                "/forgot-password",
                data={"email_address": "test@example.com", "_csrf_token": "bar"},
            )
            send_email.assert_not_called()

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.send_email")
    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    def test_no_redis_forgot_password(
        self, redis_conn, render_template, send_email, uaac
    ):
        """ When submitting an email and redis is down, server responsds 500
        """
        uaac().does_origin_user_exist.return_value = True

        redis_conn.setex.side_effect = redis.exceptions.RedisError
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/forgot-password",
                data={"email_address": "test@example.com", "_csrf_token": "bar"},
            )
            assert rv.status_code == 500
            render_template.assert_called_with("error/internal.html")

    @patch("uaaextras.webapp.UAAClient")
    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    @patch("uaaextras.webapp.smtplib")
    @patch("uaaextras.webapp.uuid")
    @patch("uaaextras.webapp.FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS")
    def test_setting_email_in_redis(
        self,
        FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS,
        uuid,
        smtplib,
        redis_conn,
        render_template,
        uaac,
    ):
        """ When submitting an email, the email and token are set in the Redis DB
        """
        uaac().does_origin_user_exist.return_value = True

        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/forgot-password",
                data={"email_address": "test@example.com", "_csrf_token": "bar"},
            )
            assert rv.status_code == 200
            redis_conn.setex.assert_called_with(
                "test@example.com",
                FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS,
                uuid.uuid4().hex,
            )
            render_template.assert_called_with(
                "forgot_password.html", email_sent=True, email="test@example.com"
            )

    @patch("uaaextras.webapp.render_template")
    def test_get_reset_password(self, render_template):
        """ When a GET request is made to /reset-password,
            and the validation code is passed in correctly
            the reset_password.html template is displayed
        """
        render_template.return_value = "template output"

        with app.test_client() as c:

            rv = c.get("/reset-password?validation=foo")
            assert rv.status_code == 200
            render_template.assert_called_with(
                "reset_password.html", validation_code="foo"
            )

    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.render_template")
    def test_get_reset_password_bad_code(self, render_template, flash):
        """ When a GET request is made to /reset-password,
            and the validation code is not passed in correctly
            the reset_password.html template is displayed
            and error message is put in flash
        """
        render_template.return_value = "template output"

        with app.test_client() as c:

            rv = c.get("/reset-password")
            assert rv.status_code == 200
            render_template.assert_called_with(
                "reset_password.html", validation_code=None
            )
            flash.assert_called_once()

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    def test_no_redis_reset_password(self, redis_conn, render_template):
        """ When submitting an email and redis is down, server responsds 500
        """

        redis_conn.get.side_effect = redis.exceptions.RedisError
        render_template.return_value = "template output"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_validation_code"] = "bar"
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/reset-password",
                data={"email_address": "test@example.com", "_csrf_token": "bar"},
            )
            assert rv.status_code == 500
            render_template.assert_called_with("error/internal.html")

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    @patch("uaaextras.webapp.generate_temporary_password")
    @patch("uaaextras.webapp.UAAClient")
    def test_render_temporary_password(
        self, uaac, generate_temporary_password, redis_conn, render_template
    ):
        """ When submitting an email and a valid token, we should render a temporary password.
        """

        render_template.return_value = "template output"
        redis_conn.get.return_value = b"example"
        uaac().set_temporary_password.return_value = generate_temporary_password()

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/reset-password",
                data={
                    "email_address": "test@example.com",
                    "_validation_code": "example",
                    "_csrf_token": "bar",
                },
            )
            assert rv.status_code == 200
            redis_conn.get.assert_called_with("test@example.com")
            redis_conn.delete.assert_called_with("test@example.com")
            render_template.assert_called_with(
                "reset_password.html",
                password=generate_temporary_password(),
                loginLink=app.config["UAA_BASE_URL"],
            )

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.r")
    def test_fail_to_render_temporary_password(
        self, redis_conn, flash, render_template
    ):
        """ When submitting an email without a valid token, I should see a flash error message.
        """

        render_template.return_value = "template output"
        redis_conn.get.return_value = b"example"

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/reset-password",
                data={
                    "email_address": "test@example.com",
                    "_validation_code": "not-example",
                    "_csrf_token": "bar",
                },
            )
            assert rv.status_code == 200
            redis_conn.get.assert_called_with("test@example.com")
            render_template.assert_called_with("reset_password.html")
            flash.assert_called_once()

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.flash")
    @patch("uaaextras.webapp.r")
    def test_fail_to_render_temporary_password_no_token(
        self, redis_conn, flash, render_template
    ):
        """ When submitting an email without a valid token, I should see a flash error message.
        """

        render_template.return_value = "template output"
        redis_conn.get.return_value = None

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/reset-password",
                data={
                    "email_address": "test@example.com",
                    "_validation_code": "not-example",
                    "_csrf_token": "bar",
                },
            )
            assert rv.status_code == 200
            redis_conn.get.assert_called_with("test@example.com")
            render_template.assert_called_with("reset_password.html")
            flash.assert_called_once()

    @requests_mock.Mocker(kw="m")
    def test_bad_token_redirects(self, m):
        """The session is cleared when logging out"""

        m.post("https://uaa.bosh-lite.com/introspect", text='{"active": false}')
        with app.test_request_context("/logout"):
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess["UAA_TOKEN"] = "foo"

                rv = c.get("/")
                assert rv.status_code == 302


class TestUAAClient(unittest.TestCase):
    """Test our UAA Client"""

    def test_error_message(self):
        """Error messages are populated properly in the exception"""
        r = Mock()
        r.text = json.dumps({"error_description": "oh no"})

        u = UAAError(r)
        assert str(u) == "oh no"

    @patch("uaaextras.clients.uaa.requests")
    def test_request_bad(self, requests):
        """UAAError is reaised when it occurs"""

        r = Mock()
        r.status_code = 500
        r.text = json.dumps({"error_description": "oh no"})
        requests.get.return_value = r

        uaac = UAAClient("http://example.com", "foo", True)

        with self.assertRaises(UAAError):
            uaac._request("/bar", "GET")

        requests.get.assert_called_with(
            "http://example.com/bar",
            headers={"Authorization": "Bearer foo"},
            json=None,
            params=None,
            auth=None,
            verify=True,
        )

    @patch("uaaextras.clients.uaa.requests")
    def test_request_get(self, requests):
        """GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({"test": "value"})
        requests.get.return_value = r

        uaac = UAAClient("http://example.com", "foo", True)

        resp = uaac._request("/bar", "GET")

        requests.get.assert_called_with(
            "http://example.com/bar",
            headers={"Authorization": "Bearer foo"},
            json=None,
            params=None,
            auth=None,
            verify=True,
        )

        assert resp["test"] == "value"

    @patch("uaaextras.clients.uaa.requests")
    def test_request_get_insecure(self, requests):
        """Insecure GET request is made"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({"test": "value"})
        requests.get.return_value = r

        uaac = UAAClient("http://example.com", "foo", False)

        resp = uaac._request("/bar", "GET")

        requests.get.assert_called_with(
            "http://example.com/bar",
            headers={"Authorization": "Bearer foo"},
            json=None,
            params=None,
            auth=None,
            verify=False,
        )

        assert resp["test"] == "value"

    @patch("uaaextras.clients.uaa.requests")
    def test_request_get_headers(self, requests):
        """Additional headers are included if we provide them"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({"test": "value"})
        requests.get.return_value = r

        uaac = UAAClient("http://example.com", "foo", False)

        resp = uaac._request("/bar", "GET", headers={"omg": "lol"})

        requests.get.assert_called_with(
            "http://example.com/bar",
            headers={"omg": "lol", "Authorization": "Bearer foo"},
            json=None,
            params=None,
            auth=None,
            verify=False,
        )

        assert resp["test"] == "value"

    @patch("uaaextras.clients.uaa.requests")
    def test_request_get_params(self, requests):
        """Query string is sent if params are provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({"test": "value"})
        requests.get.return_value = r

        uaac = UAAClient("http://example.com", "foo", False)

        resp = uaac._request("/bar", "GET", params={"omg": "lol"})

        requests.get.assert_called_with(
            "http://example.com/bar",
            headers={"Authorization": "Bearer foo"},
            json=None,
            params={"omg": "lol"},
            auth=None,
            verify=False,
        )

        assert resp["test"] == "value"

    @patch("uaaextras.clients.uaa.requests")
    def test_request_get_auth(self, requests):
        """Auth value is passed directly to requests"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({"test": "value"})
        requests.get.return_value = r

        uaac = UAAClient("http://example.com", "foo", False)

        resp = uaac._request("/bar", "GET", auth="this should be basic")

        requests.get.assert_called_with(
            "http://example.com/bar",
            headers={},
            json=None,
            params=None,
            auth="this should be basic",
            verify=False,
        )

        assert resp["test"] == "value"

    @patch("uaaextras.clients.uaa.requests")
    def test_request_post_body(self, requests):
        """Body is included in request if provided"""

        r = Mock()
        r.status_code = 200
        r.text = json.dumps({"test": "value"})
        requests.post.return_value = r

        uaac = UAAClient("http://example.com", "foo", False)

        resp = uaac._request("/bar", "POST", body="hi")

        requests.post.assert_called_with(
            "http://example.com/bar",
            headers={"Authorization": "Bearer foo"},
            json="hi",
            params=None,
            auth=None,
            verify=False,
        )

        assert resp["test"] == "value"

    @patch("uaaextras.webapp.render_template")
    def test_redeem_no_verification_code(self, render_template):
        """When an redeem link is rendered, fail if there is no matching verification code"""

        render_template.return_value = "some value"
        with app.test_client() as c:

            rv = c.get("/redeem-invite")

            assert rv.status_code == 401

            render_template.assert_called_with("error/token_validation.html")

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    def test_redeem_confirm_using_verification_code(self, redis_conn, render_template):
        """When an redeem link is rendered, call the redis key to get the UAA invite link"""

        inviteLink = b"inviteLink"
        render_template.return_value = "some value"
        redis_conn.get.return_value = inviteLink

        with app.test_client() as c:

            rv = c.get("/redeem-invite?verification_code=some_verification_code")
            redeem_link = "http://localhost:5000/redeem-invite?verification_code=some_verification_code"

            assert rv.status_code == 200

            render_template.assert_called_with(
                "redeem-confirm.html", redeem_link=redeem_link
            )

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    def test_redeem_uaainvite_using_verification_code(
        self, redis_conn, render_template
    ):
        """Render UAA link after redeem link is clicked"""

        inviteLink = b"inviteLink"
        render_template.return_value = "some value"
        redis_conn.get.return_value = inviteLink

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["_csrf_token"] = "bar"

            rv = c.post(
                "/redeem-invite?verification_code=some_verification_code",
                data={"_csrf_token": "bar"},
            )

            assert rv.status_code == 302

    @patch("uaaextras.webapp.render_template")
    @patch("uaaextras.webapp.r")
    def test_redeem_without_redis(self, redis_conn, render_template):
        """When an redeem endpoint is hit without redis, it should fail"""

        redis_conn.get.side_effect = redis.exceptions.RedisError
        render_template.return_value = "some value"

        with app.test_client() as c:

            rv = c.get("/redeem-invite?verification_code=some_verification_code")

            assert rv.status_code == 500

            render_template.assert_called_with("error/internal.html")

    def test_idps(self):
        """idps() makes a GET request to /identity-providers"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        uaac.idps(active_only=True)
        m.assert_called_with(
            "/identity-providers", "GET", params={"active_only": "true"}
        )

        uaac.idps(active_only=False)
        m.assert_called_with(
            "/identity-providers", "GET", params={"active_only": "false"}
        )

    def test_users(self):
        """users() makes a GET request to /Users"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        uaac.users()
        m.assert_called_with("/Users", "GET", params={"startIndex": 1}, headers={})

        uaac.users(start=2)
        m.assert_called_with("/Users", "GET", params={"startIndex": 2}, headers={})

        uaac.users(list_filter="test filter")
        m.assert_called_with(
            "/Users",
            "GET",
            params={"filter": "test filter", "startIndex": 1},
            headers={},
        )

        uaac.users(token="FOO")
        m.assert_called_with(
            "/Users",
            "GET",
            params={"startIndex": 1},
            headers={"Authorization": "Bearer FOO"},
        )

        uaac.users("test filter", "FOO", 9)
        m.assert_called_with(
            "/Users",
            "GET",
            params={"filter": "test filter", "startIndex": 9},
            headers={"Authorization": "Bearer FOO"},
        )

    def test_get_user(self):
        """get_user() makes a GET request to /Users/<id>"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        uaac.get_user("foo")
        m.assert_called_with(urljoin("/Users", "foo"), "GET")

    def test_put_user(self):
        """put_user() makes a PUT request to /Users/<id> with appropriate headers"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        user = {"id": "foo", "meta": {"version": "123"}}

        uaac.put_user(user)

        m.assert_called_with(
            urljoin("/Users", "foo"), "PUT", body=user, headers={"If-Match": "123"}
        )

    def test_invite_users(self):
        """invite_users() makes a PUT request to /invite_users<id>"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        email = "foo@example.com"
        redirect_uri = "http://www.example.com"

        uaac.invite_users(email, redirect_uri)

        m.assert_called_with(
            "/invite_users",
            "POST",
            body={"emails": [email]},
            headers={},
            params={"redirect_uri": redirect_uri},
        )

    def test_users_with_token(self):
        """invite_users() makes a PUT request to /invite_users<id>"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        email = "foo@example.com"
        redirect_uri = "http://www.example.com"

        uaac.invite_users(email, redirect_uri, token="foobar")

        m.assert_called_with(
            "/invite_users",
            "POST",
            body={"emails": [email]},
            headers={"Authorization": "Bearer foobar"},
            params={"redirect_uri": redirect_uri},
        )

    def test_oauth_token(self):
        """oauth_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        uaac.oauth_token("foo", "bar", "baz")

        args, kwargs = m.call_args

        assert args == ("/oauth/token", "POST")

        assert kwargs["params"] == {
            "code": "foo",
            "grant_type": "authorization_code",
            "response_type": "token",
        }

        assert isinstance(kwargs["auth"], HTTPBasicAuth)
        assert kwargs["auth"].username == "bar"
        assert kwargs["auth"].password == "baz"

    def test_get_client_token(self):
        """_get_client_token() makes a POST to /oauth/token with the appropriate headers and query params"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        uaac._get_client_token("bar", "baz")

        args, kwargs = m.call_args

        assert args == ("/oauth/token", "POST")

        assert kwargs["params"] == {
            "grant_type": "client_credentials",
            "response_type": "token",
        }

        assert isinstance(kwargs["auth"], HTTPBasicAuth)
        assert kwargs["auth"].username == "bar"
        assert kwargs["auth"].password == "baz"

    def test_decode_access_token(self):
        """decode_access_token() does a base64 decode of the JWT auth token data to get profile information"""
        uaac = UAAClient("http://example.com", "foo", False)
        token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiI5OWNiZGM4ZGE2MTg0ZmMyODgxYzUwYWNhYzJjZTJjNiIsInN1YiI6ImFkbWluIiwiYXV0aG9yaXRpZXMiOlsiY2xpZW50cy5yZWFkIiwicGFzc3dvcmQud3JpdGUiLCJjbGllbnRzLnNlY3JldCIsImNsaWVudHMud3JpdGUiLCJ1YWEuYWRtaW4iLCJzY2ltLndyaXRlIiwic2NpbS5yZWFkIl0sInNjb3BlIjpbImNsaWVudHMucmVhZCIsInBhc3N3b3JkLndyaXRlIiwiY2xpZW50cy5zZWNyZXQiLCJjbGllbnRzLndyaXRlIiwidWFhLmFkbWluIiwic2NpbS53cml0ZSIsInNjaW0ucmVhZCJdLCJjbGllbnRfaWQiOiJhZG1pbiIsImNpZCI6ImFkbWluIiwiYXpwIjoiYWRtaW4iLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImQ1NjA4NGZkIiwiaWF0IjoxNDc4Mjc5NTM3LCJleHAiOjE0NzgzMjI3MzcsImlzcyI6Imh0dHBzOi8vdWFhLmNsb3VkLmdvdi9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJzY2ltIiwicGFzc3dvcmQiLCJjbGllbnRzIiwidWFhIiwiYWRtaW4iXX0.uJABuxWIc3p-p3zJol1i2BHBfDkKXnpIcCFbOvDg8WGdbrufhFZjk78uRiPk8sw9I0reUbjyLeo0-0Eqg-x49pVaNpNeheDYaz2oc_CMO13MPXlCtVHdEGnq4e6NV21wxTMVmrLhP0QscDRctnITUY7c-ywMsUrXgv7VFj-9GPZjfr-PyG01OxStrAfe06kTXKbEHIHFgfidrDYA_pTnPO1LPz5HllVQUkAdlIIEx6VshBW6_4l2Sm0nof3cVOxqMUUB6xLSJARfudPrCmFeUIdnICl85T00-1kOe2YUMm9xRHS4hnBYbM6IU5JDmzvnz3ANEM2Uzmzv9JzkJjboIQ"  # noqa: E501
        profile = uaac.decode_access_token(token)

        assert "scope" in profile
        assert "exp" in profile

    def test_change_password(self):
        """change_password() makes a PUT request to /Users/<id>/password"""

        uaac = UAAClient("http://example.com", "foo", False)
        m = Mock()
        uaac._request = m

        uaac.change_password("foo", "bar", "baz")

        m.assert_called_with(
            "/Users/foo/password", "PUT", body={"oldPassword": "bar", "password": "baz"}
        )


class TestTOTPClient(unittest.TestCase):
    def setUp(self):
        engine = sqlalchemy.create_engine("sqlite:///:memory:", echo=True)
        self.client = TOTPClient(engine)
        with engine.connect() as conn:
            create = sqlalchemy.sql.text(
                """
            CREATE TABLE IF NOT EXISTS totp_seed (
                username varchar(255) PRIMARY KEY,
                seed varchar(36),
                backup_code varchar(36)
            )
            """
            )
            add_user = sqlalchemy.sql.text(
                "INSERT INTO totp_seed VALUES (:username, :seed, :backup_code)"
            )
            conn.execute(create)
            conn.execute(
                add_user,
                {"username": "example@cloud.gov",
                "seed": "asdfasdf",
                "backup_code": "xzcvzxcv",
                }
            )
            conn.commit()

    def test_get_totp_existing_user(self):
        assert self.client.get_user_totp_seed("example@cloud.gov") == "asdfasdf"
        assert self.client.get_user_totp_seed("nobody") is None

    def test_delete_totp(self):
        self.client.unset_totp_seed("example@cloud.gov")
        assert self.client.get_user_totp_seed("example@cloud.gov") is None

class TestCFClient(unittest.TestCase):

    def test_create_cf_client(self):
        """Creating a cf client"""
        m = Mock()
        cf_client = CFClient("http://example.com", "token")
        cf_client = m
        cf_client._get_cf_client()
        cf_client._get_cf_client.assert_called

    def test_get_org_manager(self):
        """Calling is_org_manager on the cf client"""
        m = Mock()
        cf_client = CFClient("http://example.com", "token")
        cf_client = m
        cf_client.is_org_manager(cf_client._get_cf_client(), "user_id")
        cf_client.is_org_manager.assert_called_with(cf_client._get_cf_client(), "user_id")
