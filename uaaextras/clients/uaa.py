"""A minimal wrapper for the UAA API.
https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst

This can grow over time as new endpoints are needed.  Currently it
only supports listing users and IDPs, retrieving a single user, updating a single user, and inviting users
"""

from posixpath import join as urljoin
import json
import base64
import requests
from requests.auth import HTTPBasicAuth
import logging


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

        message = self.error["error_description"]

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

    def _request(
        self,
        resource,
        method,
        body=None,
        params=None,
        auth=None,
        headers=None,
        is_json=True,
    ):
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
        if headers is None:
            headers = {}
        # build our URL from all the pieces given to us
        endpoint = urljoin(self.base_url.rstrip("/"), resource.lstrip("/"))

        # convert 'POST' to requests.post
        requests_method = getattr(requests, method.lower())

        int_headers = {}

        if self.token and auth is None:
            int_headers["Authorization"] = "Bearer " + self.token

        for kk, vv in headers.items():
            int_headers[kk] = vv
        # make the request
        response = requests_method(
            endpoint,
            params=params,
            json=body,
            verify=self.verify_tls,
            headers=int_headers,
            auth=auth,
        )

        # if we errored raise an exception
        if response.status_code >= 400:
            raise UAAError(response)

        # return the response
        if is_json:
            return json.loads(response.text)
        return response.text

    def _get_client_token(self, client_id, client_secret):
        """ Returns the client credentials token

        Args:
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above

        Raises:
            UAAError: there was an error getting the token

        Returns:
            dict: An object representing the token

        """
        response = self._request(
            "/oauth/token",
            "POST",
            params={"grant_type": "client_credentials", "response_type": "token"},
            auth=HTTPBasicAuth(client_id, client_secret),
        )
        return response.get("access_token", None)

    def idps(self, active_only=True):
        """Return a list of IDPs from UAA

        Args:
            active_only(bool, optional): Only return active IDPs

        Raises:
            UAAError: There was an error listing IDPs

        Returns:
            dict:  A list of IDPs

        """

        return self._request(
            "/identity-providers",
            "GET",
            params={"active_only": str(active_only).lower()},
        )

    def users(self, list_filter=None, token=None, start=1):
        """Return a list of users from UAA

        Args:
            list_filter(optional):  A filter to be applied to the users
            token(optional): Bearer token to use for authentication

        Raises:
            UAAError: There was an error listing users

        Returns:
            dict:  A list of users matching list_filter

        """

        headers = {}
        params = {"startIndex": start}
        if list_filter:
            params["filter"] = list_filter
        if token:
            headers = {"Authorization": "Bearer " + token}

        return self._request("/Users", "GET", params=params, headers=headers)

    def client_users(self, client_id, client_secret, list_filter=None, start=1):
        """ Return a list of users from UAA with client credentials

        Args:
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above
            list_filter(optional):  A filter to be applied to the users

        Raises:
            UAAError: there was an error changing the password

        Returns:
            dict:  A list of users matching list_filter
        """
        token = self._get_client_token(client_id, client_secret)
        return self.users(list_filter=list_filter, token=token, start=start)

    def get_user(self, user_id):
        """Retrive a user from UAA by their user id

        Args:
            user_id: The id of the user to retrieve

        Raises:
            UAAError: There was an error getting the user

        Returns:
            dict:  An object representing the user

        """

        return self._request(urljoin("/Users", user_id), "GET")

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
            urljoin("/Users", user["id"]),
            "PUT",
            body=user,
            headers={"If-Match": str(user["meta"]["version"])},
        )

    def client_invite_users(self, client_id, client_secret, email, redirect_uri):
        """Invite a user to UAA with client credentials

        Args:
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above
            email(str, list(str)): An email or list of emails to invite
            redirect_uri(str): Where to send the users after they have accepted their invite

        Raises:
            UAAError: There was an error inviting the user

        Returns:
            dict:   An object representing the invite, including an inviteLink which should be emailed
                    to the user to validate their email address.  Visiting the link will activate the user.
        """
        token = self._get_client_token(client_id, client_secret)
        return self.invite_users(email, redirect_uri, token)

    def invite_users(self, email, redirect_uri, token=None):
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

        headers = {}

        if not isinstance(email, list):
            email = [email]

        if token:
            headers = {"Authorization": "Bearer " + token}

        return self._request(
            "/invite_users",
            "POST",
            params={"redirect_uri": redirect_uri},
            headers=headers,
            body={"emails": email},
        )

    def decode_access_token(self, token):
        """Decodes an access token

        Args:
            token(str): An UUA access token

        Returns:
            dict: An object representing the decoded access token.

        """
        payload = token.split(".")[1]
        missing_padding = len(payload) % 4
        if missing_padding != 0:
            payload += "=" * (4 - missing_padding)
        decoded_token = str(base64.b64decode(payload), "utf-8")
        return json.loads(decoded_token)

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
            "/oauth/token",
            "POST",
            params={
                "code": code,
                "grant_type": "authorization_code",
                "response_type": "token",
            },
            auth=HTTPBasicAuth(client_id, client_secret),
        )

    def change_password(self, user_id, old_password, new_password):
        """Changes a users password at their own request

        Args:
            user_id: the user id to act on
            old_password: the users current password
            new_password: the users desired password

        Raises:
            UAAError: there was an error changing the password

        Returns:
            dict: an object representing the response with user_id and code
        """
        return self._request(
            urljoin("/Users", user_id, "password"),
            "PUT",
            body={"oldPassword": old_password, "password": new_password},
        )

    def set_temporary_password(self, client_id, client_secret, username, new_password):
        """ Changes password on behalf of the user with client credentials

        Args:
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above
            user_id: the user id to act on
            new_password: the users desired password

        Raises:
            UAAError: there was an error changing the password

        Returns:
            boolean: Success/failure
        """
        list_filter = 'userName eq "{0}"'.format(username)
        userList = self.client_users(client_id, client_secret, list_filter=list_filter)

        if len(userList["resources"]) > 0:
            user_id = userList["resources"][0]["id"]
            token = self._get_client_token(client_id, client_secret)
            self._request(
                urljoin("/Users", user_id, "password"),
                "PUT",
                body={"password": new_password},
                headers={"Authorization": "Bearer " + token},
            )
            return True

        return False

    def does_origin_user_exist(self, client_id, client_secret, username, origin):
        """ Checks to see if a user exists with a given origin

        Args:
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above
            user_id: the username to check
            origin: the UAA origin

        Raises:
            UAAError: there was an error changing the password

        Returns:
            boolean: user exists or not
        """

        list_filter = 'userName eq "{0}" and origin eq "{1}"'.format(username, origin)
        userList = self.client_users(client_id, client_secret, list_filter=list_filter)

        if len(userList["resources"]) > 0:
            return True

        return False

    def create_user(
        self,
        user_id,
        given_name,
        family_name,
        primary_email,
        password=None,
        origin=None,
    ):
        """ Create a user in UAA
        Args:
            user_id
            given_name
            family_name
            primary_email
            password
            origin
        """
        params = {
            "name": {"familyName": family_name, "givenName": given_name},
            "emails": [{"primary": True, "value": primary_email}],
            "userName": user_id,
        }
        if password:
            params["password"] = password
        if origin:
            params["origin"] = origin
        return self._request("/Users", "POST", body=params)

    def delete_user(self, user_id):
        """ Delete a user from UAA

        Args:
            client_id: The oauth client id that this code was generated for
            client_secret: The secret for the client_id above
            user_id: the id of the user to delete

        Raises:
            UAAError: there was an error deleting the user

        Returns:
            dict:  A list of users matching list_filter
        """
        return self._request(f"/Users/{user_id}", "DELETE")

    def invalidate_tokens(self, user_id, zone_id=None, zone_subdomain=None) -> None:
        """
        Invalidate all the tokens for a given user.
        Args:
            token: a token with permissions to invalidate the tokens
            user_id: the id of the user to log out
        Returns:
            None
        """
        headers = dict()
        if zone_id:
            headers["X-Identity-Zone-Id"] = zone_id
            if zone_subdomain:
                headers["X-Identity-Zone-Subdomain"] = zone_subdomain
        self._request(
            urljoin("/oauth/token/revoke/user", user_id),
            "GET",
            headers=headers,
            is_json=False,
        )


    def check_token_valid(self, maybe_valid_token, client_id, client_secret) -> bool:
        """
        Check whether the provided token is valid, using the client_id and client_secret to authenticate
        """
        url = urljoin(self.base_url.rstrip("/"), "/introspect".lstrip("/"))
        response = requests.post(url, data={"token": maybe_valid_token}, auth=HTTPBasicAuth(client_id, client_secret))
        if response.status_code != 200:
            return False
        return response.json().get("active", False)
