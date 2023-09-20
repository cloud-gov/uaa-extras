#!/bin/sh

set -ex

pip install tox colorama==0.4.4
(cd ./cg-uaa-extras-app && tox)
