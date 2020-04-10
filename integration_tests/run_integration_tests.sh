#!/bin/bash

# required environment vars:
# EXTRAS_URL: the url for the uaaextras app, e.g. https://account.example.com
# UAA_URL: the login url for uaa, e.g. https://login.example.com
# IDP_URL: the url for the shibboleth IDP, e.g. https://idp.example.com
# IDP_NAME: the name of the shibboleth IDP, as UAA sees it, e.g. example.com
# TEST_USERNAME: the username of a user to run through tests
# TEST_PASSWORD: the password for the user
#
# optional:
# TEST_TOTP: the seed of the user's TOTP. Can be omitted if the user does not yet have a TOTP token set
#

for required_var in EXTRAS_URL UAA_URL IDP_URL TEST_USERNAME TEST_PASSWORD IDP_NAME; do
    if [[ -z ${!required_var} ]]; then
        echo "Please set ${required_var}"
        exit 1
    fi
done

if [[ -z ${TEST_TOTP} ]]; then
    echo "TEST_TOTP is unset. Hope your user doesn't have a registered MFA!"
fi

pushd "$(dirname "${BASH_SOURCE[0]}")"

python3 -m  venv venv

source venv/bin/activate

python3 -m pip install -r requirements.txt

pytest
return=$?

deactivate

popd
exit ${return}
