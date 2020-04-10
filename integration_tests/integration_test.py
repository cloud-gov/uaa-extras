import typing

from bs4 import BeautifulSoup
import pyotp
import requests


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

    def log_in(self, username, password, totp_seed=None) -> typing.Tuple[str, bool]:
        """
        log in using the shibboleth totp IDP. 
        handles registering totp if user does not have one currently
        returns a tuple of str, bool representing the user's totp_seed, and whether a new totp was registered
        """
        if totp_seed is not None:
            totp = pyotp.TOTP(totp_seed)
        totp_updated = False
        # query param used to track steps. Probably better to get it from responses, but /shrug/
        s = 1
        r = self.s.get(self.uaa_url + "/login")
        params = {
            "returnIDParam": "idp",
            "entityID": self.uaa_url[8:],
            "idp": self.idp_name,
            "isPassive": "true",
        }
        r = self.s.get(f"{self.uaa_url}/saml/discovery", params=params)
        soup = BeautifulSoup(r.text, features="html.parser")
        saml_request = soup.find(attrs={"name": "SAMLRequest"}).attrs["value"]
        relay_state = soup.find(attrs={"name": "RelayState"}).attrs["value"]
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        r = self.s.post(f"{self.idp_url}/profile/SAML2/POST/SSO", data=payload)
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
        soup = BeautifulSoup(r.text, features="html.parser")
        form = soup.find("form")
        next_url = form.attrs["action"]
        print(form)
        r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
        soup = BeautifulSoup(r.text, features="html.parser")
        form = soup.find("form")
        next_url = form.attrs["action"]
        print(form)
        payload = {
            "j_username": username,
            "j_password": password,
            "_eventId_proceed": "",
        }
        r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
        soup = BeautifulSoup(r.text, features="html.parser")
        form = soup.find("form")
        print(form)
        next_url = form.attrs["action"]
        if form is not None and "barcode" in str(form):
            totp_updated = True
            totp_seed = soup.find("strong").string
            totp = pyotp.TOTP(totp_seed)
            payload = {
                "j_tokenNumber": totp.now(),
                "_eventId_proceed": "",
                "state": "$state",
            }
            r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
            soup = BeautifulSoup(r.text, features="html.parser")
            form = soup.find("form")
            next_url = form.attrs["action"]
        payload = {
            "j_tokenNumber": totp.now(),
            "_eventId_proceed": "",
            "state": "$state",
        }
        r = self.s.post(f"{self.idp_url}{next_url}", data=payload)
        soup = BeautifulSoup(r.text, features="html.parser")
        saml_request = soup.find(attrs={"name": "SAMLResponse"}).attrs["value"]
        relay_state = soup.find(attrs={"name": "RelayState"}).attrs["value"]
        action = soup.find("form").attrs["action"]
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        r = self.s.post(action, data=payload)
        r = self.s.get(self.uaa_url)
        return totp_seed, totp_updated

    def log_out(self) -> None:
        self.s.get(f"{self.uaa_url}/logout.do")
        self.s = requests.Session()
