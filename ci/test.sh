#!/bin/sh

set -ex

pip install tox
(cd ./cg-uaa-invite-app && tox)
