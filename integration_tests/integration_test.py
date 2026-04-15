import typing

from bs4 import BeautifulSoup
import pyotp
import requests

# CSRF Element looks like <input type="hidden" name="csrf_token" value="_97d8d610c343b1cdd5386aedfcc5451d2ec32e97">


class IntegrationTestClient:
    def __init__(self, extras_url, idp_url, uaa_url, idp_name) -> None:
        self.s = requests.Session()
        self.extras_url = extras_url
        self.idp_url = idp_url
        self.uaa_url = uaa_url
        self.idp_name = idp_name

    def get_page(self, page, **kwargs) -> requests.models.Response:
        url = self.extras_url + page
        return self.s.get(url, **kwargs)

    def post_to_page(self, page, **kwargs) -> requests.models.Response:
        url = self.extras_url + page
        return self.s.post(url, **kwargs)

    def uaa_pick_idp(self) -> str:
        r = self.s.get(self.uaa_url + "/login")
        r = self.s.get(f"{self.uaa_url}/saml2/authenticate/{self.idp_name}")
        soup = BeautifulSoup(r.text, features="html.parser")
        saml_request = soup.find(attrs={"name": "SAMLRequest"}).attrs["value"]
        relay_state = soup.find(attrs={"name": "RelayState"}).attrs["value"]
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        r = self.s.post(f"{self.idp_url}/profile/SAML2/POST/SSO", data=payload)
        return r

    def idp_start_log_in(self, url, csrf):
        payload = {
            "shib_idp_ls_exception.shib_idp_session_ss": "",
            "shib_idp_ls_success.shib_idp_session_ss": "false",
            "shib_idp_ls_value.shib_idp_session_ss": "",
            "shib_idp_ls_exception.shib_idp_persistent_ss": "",
            "shib_idp_ls_success.shib_idp_persistent_ss": "false",
            "shib_idp_ls_value.shib_idp_persistent_ss": "",
            "shib_idp_ls_supported": "true",
            "_eventId_proceed": "",
        }
        if csrf is not None:
            payload["csrf_token"] = csrf
        # Check if url is already a full URL
        if url.startswith("http://") or url.startswith("https://"):
            full_url = url
        else:
            # Only concatenate if it's a relative path
            full_url = f"{self.idp_url}{url}"
        r = self.s.post(full_url, data=payload)
        return r

    def idp_username_password_login(self, url, username, password, csrf):
        payload = {
            "j_username": username,
            "j_password": password,
            "_eventId_proceed": "",
        }
        if csrf is not None:
            payload["csrf_token"] = csrf
        # Check if url is already a full URL
        if url.startswith("http://") or url.startswith("https://"):
            full_url = url
        else:
            # Only concatenate if it's a relative path
            full_url = f"{self.idp_url}{url}"
        r = self.s.post(full_url, data=payload)
        return r

    def idp_totp_login(self, body, totp_seed=None) -> typing.Tuple[str, bool, str]:
        totp_updated = False
        soup = BeautifulSoup(body, features="html.parser")
        form = soup.find("form")
        csrf = get_csrf_for_form(form)
        next_url = form.attrs["action"]
        if totp_seed is not None:
            totp = pyotp.TOTP(totp_seed)
        if form is not None and "barcode" in str(form):
            totp_updated = True
            totp_seed = soup.find("strong").string
            totp = pyotp.TOTP(totp_seed)
            payload = {
                "j_tokenNumber": totp.now(),
                "_eventId_proceed": "",
                "state": "$state",
            }
            if csrf is not None:
                payload["csrf_token"] = csrf
            # Check if url is already a full URL
            if next_url.startswith("http://") or next_url.startswith("https://"):
                full_url = next_url
            else:
                # Only concatenate if it's a relative path
                full_url = f"{self.idp_url}{next_url}"
            r = self.s.post(full_url, data=payload)
            soup = BeautifulSoup(r.text, features="html.parser")
            form = soup.find("form")
            csrf = get_csrf_for_form(form)
            next_url = form.attrs["action"]
        payload = {
            "j_tokenNumber": totp.now(),
            "_eventId_proceed": "",
            "state": "$state",
        }
        if csrf is not None:
            payload["csrf_token"] = csrf
        # Check if url is already a full URL
        if next_url.startswith("http://") or next_url.startswith("https://"):
            full_url = next_url
        else:
            # Only concatenate if it's a relative path
            full_url = f"{self.idp_url}{next_url}"
        r = self.s.post(full_url, data=payload)
        return totp_seed, totp_updated, r

    def reset_session(self) -> None:
        """Reset the session to start fresh"""
        self.s = requests.Session()

    def log_in(self, username, password, totp_seed=None) -> typing.Tuple[str, bool]:
        """
        log in using the shibboleth totp IDP.
        handles registering totp if user does not have one currently
        returns a tuple of str, bool representing the user's totp_seed, and whether a new totp was registered
        """

        r = self.uaa_pick_idp()
        soup = BeautifulSoup(r.text, features="html.parser")
        form = soup.find("form")
        next_url = form.attrs["action"]
        csrf = get_csrf_for_form(form)

        r = self.idp_start_log_in(next_url, csrf)
        soup = BeautifulSoup(r.text, features="html.parser")

        # Check if we got a SAML error, which means we need to start fresh
        if r.url.endswith("/saml_error") or "saml_error" in r.url:
            # Reset the session and try again
            self.reset_session()
            r = self.uaa_pick_idp()
            soup = BeautifulSoup(r.text, features="html.parser")
            form = soup.find("form")
            next_url = form.attrs["action"]
            csrf = get_csrf_for_form(form)
            r = self.idp_start_log_in(next_url, csrf)
            soup = BeautifulSoup(r.text, features="html.parser")
        form = soup.find("form")
        if form is None:
            raise ValueError(
                f"No form found in idp_start_log_in response. URL: {r.url}, Status: {r.status_code}"
            )
        next_url = form.attrs["action"]
        csrf = get_csrf_for_form(form)
        r = self.idp_username_password_login(next_url, username, password, csrf)
        totp_seed, totp_updated, r = self.idp_totp_login(r.text, totp_seed)

        soup = BeautifulSoup(r.text, features="html.parser")
        saml_request = soup.find(attrs={"name": "SAMLResponse"}).attrs["value"]
        relay_state = soup.find(attrs={"name": "RelayState"}).attrs["value"]
        form = soup.find("form")
        action = form.attrs["action"]
        csrf = get_csrf_for_form(form)

        payload = dict(RelayState=relay_state, SAMLResponse=saml_request)
        if csrf is not None:
            payload["csrf_token"] = csrf
        r = self.s.post(action, data=payload)

        return totp_seed, totp_updated

    def log_out(self) -> None:
        self.s.get(f"{self.uaa_url}/logout.do")
        self.s = requests.Session()


def get_csrf_for_form(form):
    def is_csrf_token(input):
        return input.has_attr("name") and input.attrs["name"] == "csrf_token"

    token_input = form.find(is_csrf_token)
    if token_input is not None:
        return token_input.attrs["value"]
