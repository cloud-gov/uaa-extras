#!/bin/sh

set -ex

apt update
apt install -y libpq-dev

pyenv install -s $(cat ./cg-uaa-extras-app/.python-version)
pip install tox
(cd ./cg-uaa-extras-app && tox)
