import os

from bs4 import BeautifulSoup
import pytest

from .integration_test import IntegrationTestClient


@pytest.fixture
def config():
    config = {}
    urls = {}
    urls["uaa"] = os.environ["UAA_URL"]
    urls["extras"] = os.environ["EXTRAS_URL"]
    urls["idp"] = os.environ["IDP_URL"]
    for url in urls:
        if not urls[url][0:4] == "http":
            urls[url] = "https://" + urls[url]
    config["urls"] = urls
    config["idp_name"] = os.environ["IDP_NAME"]
    return config


@pytest.fixture
def user():
    user = {}
    user["name"] = os.environ["TEST_USERNAME"]
    user["password"] = os.environ["TEST_PASSWORD"]
    user["token"] = os.getenv("TEST_TOKEN")
    return user


@pytest.fixture
def unauthenticated(config):
    itc = IntegrationTestClient(
        config["urls"]["extras"],
        config["urls"]["idp"],
        config["urls"]["uaa"],
        config["idp_name"],
    )
    return itc


@pytest.fixture
def authenticated(unauthenticated, user):
    token, changed = unauthenticated.log_in(
        user["name"], user["password"], user["token"]
    )
    if changed:
        os.environ["TEST_TOKEN"] = token
    return unauthenticated


@pytest.mark.parametrize("page", ["/invite", "/change-password", "/first-login"])
def test_unauthenticated_pages_redirect(unauthenticated, page, config):
    r = unauthenticated.get_page(page)
    assert r.status_code == 200
    assert r.url == config["urls"]["uaa"] + "/login"


@pytest.mark.parametrize("page", ["/invite", "/change-password"])
def test_authenticated_pages_work(authenticated, page, config):
    r = authenticated.get_page(page)
    assert r.status_code == 200
    assert r.url == config["urls"]["extras"] + page


def test_change_password(authenticated, config, user):
    r = authenticated.get_page("/change-password")
    soup = BeautifulSoup(r.text, features="html.parser")
    csrf = soup.find(attrs={"name": "_csrf_token"}).attrs["value"]
    data = {
        "old_password": user["password"],
        "new_password": "a_severely_insecure_password",
        "repeat_password": "a_severely_insecure_password",
        "_csrf_token": csrf,
    }
    r = authenticated.post_to_page("/reset-password", data=data)
    assert r.status_code == 200

    # set the password back so we don't confuse the other tests
    r = authenticated.get_page("/change-password")
    soup = BeautifulSoup(r.text, features="html.parser")
    csrf = soup.find(attrs={"name": "_csrf_token"}).attrs["value"]
    data = {
        "old_password": "a_severely_insecure_password",
        "new_password": user["password"],
        "repeat_password": user["password"],
        "_csrf_token": csrf,
    }
