#!/bin/sh

set -ex

apt update
apt install -y libpq-dev

pip install tox
(cd ./cg-uaa-extras-app && tox)
