#!/bin/sh

set -ex

apt update
apt install -y libpq-dev

pyenv install -s $(cat $(pyenv version-file))
pip install tox
(cd ./cg-uaa-extras-app && tox)
