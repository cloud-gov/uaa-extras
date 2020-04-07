#!/bin/bash

for required_var in EXTRAS_URL UAA_URL IDP_URL TEST_USERNAME TEST_PASSWORD TEST_TOKEN IDP_NAME; do
    if [[ -z ${!required_var} ]]; then
        echo "Please set ${required_var}"
        exit 1
    fi
done

pushd "$(dirname "${BASH_SOURCE[0]}")"

python3 -m  venv venv

source venv/bin/activate

python3 -m pip install -r requirements.txt

pytest
return=$?

deactivate

popd
exit ${return}
