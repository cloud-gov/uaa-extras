from setuptools import setup, find_packages

setup(
    name="uaaextras",
    version="0.0.1",
    description="A simple UI for UAA /invite_users endpoint and password resets",
    url="https://github.com/cloud-gov/cg-uaa-extras",
    author="Chris Nelson",
    author_email="cnelson@cnelson.org",
    license="Public Domain",
    packages=find_packages(exclude=["integration_tests*", "test"]),
    install_requires=[
    ],
)
