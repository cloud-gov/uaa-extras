#!/bin/bash

# required environment vars:
# EXTRAS_URL: the url for the uaaextras app, e.g. https://account.example.com
# UAA_URL: the login url for uaa, e.g. https://login.example.com
# IDP_URL: the url for the shibboleth IDP, e.g. https://idp.example.com
# IDP_NAME: the name of the shibboleth IDP, as UAA sees it, e.g. example.com
#
# optional:
#

for required_var in EXTRAS_URL UAA_URL IDP_URL IDP_NAME UAA_USER UAA_SECRET; do
    if [[ -z ${!required_var} ]]; then
        echo "Please set ${required_var}"
        exit 1
    fi
done

pushd "$(dirname "${BASH_SOURCE[0]}")"

    if [[ -z "${NO_CREATE_ENV}" ]]; then
        python3 -m venv venv
        source venv/bin/activate
        python3 -m pip install -r requirements.txt

        pushd ../
            python3 -m pip install -r requirements.txt
            python3 setup.py install
        popd
    fi
    pytest -v
    return=$?

    if [[ -z "${NO_CREATE_ENV}" ]]; then
        deactivate
    fi

popd
exit ${return}
