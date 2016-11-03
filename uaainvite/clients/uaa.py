"""A minimal wrapper for the UAA API.
https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst

This can grow over time as new endpoints are needed.  Currently it
only supports listing users and IDPs, retrieving a single user, updating a single user, and inviting users
"""

from posixpath import join as urljoin
import json
import jwt
import requests
from requests.auth import HTTPBasicAuth


class UAAError(RuntimeError):
    """This exception is raised when the UAA API returns a status code >= 400

    Attributes:
        response:   The full response object from requests that was returned
        error:  The body of the response json decoded

    Args:
        response: The full response object that is causing this exception to be raised

    """
    def __init__(self, response):
        self.response = response
        self.error = json.loads(response.text)

        message = self.error['error_description']

        super(UAAError, self).__init__(message)


class UAAClient(object):
    """A minimal client for the UAA API

    Args:
        base_url: The URL to your UAA instance
        token: A bearer token.
        verify_tls: Do we validate certs when talking to UAA
    """
    def __init__(self, base_url, token, verify_tls=True):
        self.base_url = base_url
        self.token = token
        self.verify_tls = verify_tls

    def _request(self, resource, method, body=None, params=None, auth=None, headers={}):
        """Make a request to the UAA API.

        Args:
            resource: The API method you wish to call (example: '/Users')
            method: The method to use when making the request GET/POST/etc
            body (optional): An json encodeable object which will be included as the body
            of the request
            params (optional): Query string parameters that are included in the request
            auth (optional): A requests.auth.* instance
            headers (optional): A list of headers to include in the request

        Raises:
            UAAError: An error occured making the request

        Returns:
            dict:   The parsed json response

        """
        # build our URL from all the pieces given to us
        endpoint = urljoin(
            self.base_url.rstrip('/'),
            resource.lstrip('/')
        )

        # convert 'POST' to requests.post
        requests_method = getattr(requests, method.lower())

        int_headers = {}

        if self.token and auth is None:
            int_headers['Authorization'] = 'Bearer ' + self.token

        for kk, vv in headers.items():
            int_headers[kk] = vv

        # make the request
        response = requests_method(
            endpoint,
            params=params,
            json=body,
            verify=self.verify_tls,
            headers=int_headers,
            auth=auth
        )

        # if we errored raise an exception
        if response.status_code >= 400:
            raise UAAError(response)

        # return the response
        return json.loads(response.text)

    def idps(self, active_only=True):
        """Return a list of IDPs from UAA

        Args:
            active_only(bool, optional): Only return active IDPs

        Raises:
            UAAError: There was an error listing IDPs

        Returns:
            dict:  A list of IDPs

        """

        return self._request('/identity-providers', 'GET', params={'active_only': str(active_only).lower()})

    def users(self, list_filter=None):
        """Return a list of users from UAA

        Args:
            list_filter(optional):  A filter to be applied to the users

        Raises:
            UAAError: There was an error listing users

        Returns:
            dict:  A list of users matching list_filter

        """

        params = None
        if list_filter:
            params = {'filter': list_filter}

        return self._request('/Users', 'GET', params=params)

    def get_user(self, user_id):
        """Retrive a user from UAA by their user id

        Args:
            user_id: The id of the user to retrieve

        Raises:
            UAAError: There was an error getting the user

        Returns:
            dict:  An object representing the user

        """

        return self._request(urljoin('/Users', user_id), 'GET')

    def put_user(self, user):
        """Update a user in UAAA

        Args:
            user: A dict describing the user matching the format returned by get_user

        Raises:
            UAAError: There was an error updating the user

        Returns:
            dict:  An object representing the user

        """

        return self._request(
            urljoin('/Users', user['id']),
            'PUT',
            body=user,
            headers={'If-Match': user['meta']['version']}
        )

    def invite_users(self, email, redirect_uri):
        """Invite a user to UAA

        Args:
            email(str, list(str)): An email or list of emails to invite
            redirect_uri(str): Where to send the users after they have accepted their invite

        Raises:
            UAAError: There was an error inviting the user

        Returns:
            dict:   An object representing the invite, including an inviteLink which should be emailed
                    to the user to validate their email address.  Visiting the link will activate the user.
        """

        if not isinstance(email, list):
            email = [email]

        return self._request('/invite_users', 'POST', params={'redirect_uri': redirect_uri}, body={'emails': email})

    def decode_access_token(self, token):
        """Decodes an access token

        Args:
            token(str): An UUA access token

        Returns:
            dict: An object representing the decoded access token.

        """

        try:
            decoded_token = jwt.decode(token)
            return json.loads(decoded_token)
        except:
            logging.exception('An invalid access token was decoded with jwt')
            return render_template('error/token_validation.html'), 401

    def oauth_token(self, code, client_id, client_secret):
        """Use an authorization code to retrieve a bearer token from UAA

        Args:
            code: The authorization code
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above

        Raises:
            UAAError: There was an error retrieving the token

        Returns:
            dict:  An object representing the token


        """

        return self._request(
            '/oauth/token',
            'POST',
            params={
                'code': code,
                'grant_type': 'authorization_code',
                'response_type': 'token'
            },
            auth=HTTPBasicAuth(client_id, client_secret)
        )
