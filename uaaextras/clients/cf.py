import logging
from cloudfoundry_client.client import CloudFoundryClient
from cloudfoundry_client.errors import InvalidStatusCode

logger = logging.getLogger(__name__)

class CFClient(object):
    """
    A minimal client for CF
    """

    def __init__(self, target_endpoint, token):
        self.target_endpoint = target_endpoint
        self.token = token

    def _get_cf_client(self):
        client = CloudFoundryClient(self.target_endpoint)
        client._access_token = self.token
        return client

    def is_org_manager(self, client, user_id):
        for role in client.v3.roles.list(user_guids=user_id):
            if role['type'] == 'organization_manager':
                return True
        return False
