import logging
from cloudfoundry_client.client import CloudFoundryClient
from cloudfoundry_client.errors import InvalidStatusCode

logger = logging.getLogger(__name__)

def get_cf_client(target_endpoint, access_token):
    client = CloudFoundryClient(target_endpoint)
    client._access_token = access_token
    return client

def is_org_manager(client, user_id):
    return 'organization_manager' in client.v3.roles.list(user_guids=user_id)
