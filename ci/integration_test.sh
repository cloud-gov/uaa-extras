#!/bin/bash -ex

function cleanup () {
    uaac user delete ${TEST_USERNAME}
}
user_suffix=$(cat /dev/urandom | env LC_CTYPE=C tr -dc 'a-z0-9' | fold -w 32 | head -n 1)
export TEST_USERNAME="noreply+${user_suffix}@cloud.gov"
export TEST_PASSWORD=$(cat /dev/urandom | env LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

# log in
uaac target ${UAA_TARGET}
uaac token client get ${UAA_USER} -s ${UAA_SECRET}

# create our users
uaac user add --origin ${IDP_NAME} -e ${TEST_USERNAME} ${TEST_USERNAME}
uaac password set ${TEST_USERNAME} -p ${TEST_PASSWORD}

# always delete the test user
trap cleanup EXIT

pushd "$(dirname "${BASH_SOURCE[0]}")"
ci_dir=$(pwd)
popd
${ci_dir}/../integration_tests/run_integration_tests.sh
