#!/bin/sh

set -ex

pip install tox
(cd ./cg-uaa-extras-app && tox)
