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
        form = soup.find("form")
        next_url = form.attrs["action"]
        saml_request = soup.find(attrs={"name": "SAMLRequest"}).attrs["value"]
        relay_state = soup.find(attrs={"name": "RelayState"}).attrs["value"]
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
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
        r = self.s.post(f"{self.idp_url}{url}", data=payload)
        return r

    def idp_username_password_login(self, url, username, password, csrf):
        payload = {
            "j_username": username,
            "j_password": password,
            "_eventId_proceed": "",
        }
        if csrf is not None:
            payload["csrf_token"] = csrf
        r = self.s.post(f"{self.idp_url}{url}", data=payload)
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
            r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
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
        r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
        return totp_seed, totp_updated, r


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
        form = soup.find("form")
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
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        if csrf is not None:
            payload["csrf_token"] = csrf
        r = self.s.post(action, data=payload)
        r = self.s.get(self.uaa_url)
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
