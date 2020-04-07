from urllib.parse import quote
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

    def log_in(self, username, password, totp_seed) -> None:
        totp = pyotp.TOTP(totp_seed)
        r = self.s.get(self.uaa_url + '/login')
        params = {'returnIDParam': 'idp', 'entityID': self.uaa_url[8:], 'idp': self.idp_name, 'isPassive': 'true'}
        r = self.s.get(f'{self.uaa_url}/saml/discovery', params=params)
        soup = BeautifulSoup(r.text, features="html.parser")
        saml_request = soup.find(attrs={'name': 'SAMLRequest'}).attrs['value']
        relay_state = soup.find(attrs={'name': 'RelayState'}).attrs['value']
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        r = self.s.post(f'{self.idp_url}/profile/SAML2/POST/SSO', data=payload)
        payload = {
            'shib_idp_ls_exception.shib_idp_session_ss': '',
            'shib_idp_ls_success.shib_idp_session_ss': 'false',
            'shib_idp_ls_value.shib_idp_session_ss': '',
            'shib_idp_ls_exception.shib_idp_persistent_ss': '',
            'shib_idp_ls_success.shib_idp_persistent_ss': 'false',
            'shib_idp_ls_value.shib_idp_persistent_ss': '',
            'shib_idp_ls_supported': 'true',
            '_eventId_proceed': '',
        }
        r = self.s.post(f'{self.idp_url}/profile/SAML2/POST/SSO', params={'execution': 'e1s1'}, data=payload)
        payload = {
            'j_username': username,
            'j_password': password,
            '_eventId_proceed':''
        }
        r = self.s.post(f'{self.idp_url}/profile/SAML2/POST/SSO', params={'execution': 'e1s2'}, data=payload)
        payload = {
            'j_tokenNumber': totp.now(),
            '_eventId_proceed': '',
            'state': '$state'
        }
        r = self.s.post(f'{self.idp_url}/profile/SAML2/POST/SSO', params={'execution': 'e1s3'}, data=payload)
        soup = BeautifulSoup(r.text, features="html.parser")
        saml_request = soup.find(attrs={'name': 'SAMLResponse'}).attrs['value']
        relay_state = soup.find(attrs={'name': 'RelayState'}).attrs['value']
        action = soup.find('form').attrs['action']
        payload = dict(RelayState=relay_state, SAMLRequest=saml_request)
        r = self.s.post(action, data=payload)
        r = self.s.get(self.uaa_url)

    def log_out(self) -> None:
        self.s.get(f'{self.uaa_url}/logout.do')
        self.s = requests.Session()

