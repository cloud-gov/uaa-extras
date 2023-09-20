#!/bin/sh

set -ex

cd ./cg-uaa-extras-app
pip install -r requirements-ci.txt
tox
