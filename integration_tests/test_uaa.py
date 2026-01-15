import os
import random
import string

from bs4 import BeautifulSoup
import pytest

from uaaextras.clients import UAAClient
from .integration_test import IntegrationTestClient, get_csrf_for_form


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
    config["uaa_client"] = os.environ["UAA_USER"]
    config["uaa_secret"] = os.environ["UAA_SECRET"]
    return config


@pytest.fixture
def uaa(config):
    uaac = UAAClient(config["urls"]["uaa"], None, verify_tls=True)
    token = uaac._get_client_token(config["uaa_client"], config["uaa_secret"])
    uaac.token = token
    return uaac


@pytest.fixture
def user(uaa, config):
    user = {}
    user["name"] = (
        "noreply+" + "".join(random.choices(string.ascii_lowercase, k=8)) + "@cloud.gov"
    )
    user["password"] = "".join(
        random.choices(
            string.ascii_lowercase + string.ascii_uppercase + string.digits, k=20
        )
    )
    r = uaa.create_user(
        user["name"],
        "unimportant",
        "alsounimportant",
        user["name"],
        password=user["password"],
        origin="cloud.gov",
    )
    uaa.set_temporary_password(
        config["uaa_client"], config["uaa_secret"], user["name"], user["password"]
    )
    yield user
    uaa.delete_user(r["id"])


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
    token, changed = unauthenticated.log_in(user["name"], user["password"])
    if changed:
        user["token"] = token
    return unauthenticated


def get_csrf(page_text) -> str:
    page = BeautifulSoup(page_text, features="html.parser")
    csrf = page.find(attrs={"name": "_csrf_token"}).attrs["value"]
    return csrf


@pytest.mark.parametrize("page", ["/invite", "/change-password", "/first-login"])
def test_unauthenticated_pages_redirect(unauthenticated, page, config):
    r = unauthenticated.get_page(page)
    assert r.status_code == 200
    assert r.url == config["urls"]["uaa"] + "/login"


# NOTE: Needs to be first test as long as we do not have a totp-reset method
def test_login_no_totp(unauthenticated, config, user):
    # log in to get/set our totp
    token, changed = unauthenticated.log_in(user["name"], user["password"])
    assert changed
    # log out, so log in will work
    unauthenticated.log_out()

    # log in again to make sure we have the right totp
    _, changed = unauthenticated.log_in(user["name"], user["password"], token)
    assert not changed


def test_reset_totp(authenticated, user):
    # get the page so we have a CSRF
    r = authenticated.get_page("/reset-totp")
    assert r.status_code == 200
    soup = BeautifulSoup(r.text, features="html.parser")
    form = soup.find("form")
    csrf = get_csrf_for_form(form)
    # actually reset our totp
    r = authenticated.post_to_page("/reset-totp", data={"_csrf_token": csrf})
    assert r.status_code == 200

    # reset-totp is supposed to log a user out. Logging in should reset our totp
    token, changed = authenticated.log_in(user["name"], user["password"])
    assert changed


@pytest.mark.parametrize("page", ["/invite", "/change-password"])
def test_authenticated_pages_work(authenticated, page, config):
    r = authenticated.get_page(page)
    assert r.status_code == 200
    assert r.url == config["urls"]["extras"] + page


def test_change_password(authenticated, config, user):
    r = authenticated.get_page("/change-password")
    soup = BeautifulSoup(r.text, features="html.parser")
    form = soup.find("form")
    csrf = get_csrf_for_form(form)
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
    form = soup.find("form")
    csrf = get_csrf_for_form(form)
    data = {
        "old_password": "a_severely_insecure_password",
        "new_password": user["password"],
        "repeat_password": user["password"],
        "_csrf_token": csrf,
    }


@pytest.mark.skip("Not done yet")
def test_invites_happy_path(authenticated, config):
    if "dev" in config["urls"]["uaa"]:
        # alternate path: use dev, but expect the request to fail
        # email fails, but its also the last thing to happen, so the user
        # is created and their invite info can still be fetched from Redis
        pytest.skip("Can't test functions that require email in dev")
    r = authenticated.get_page("/invite")
    soup = BeautifulSoup(r.text, features="html.parser")
    form = soup.find("form")
    csrf = get_csrf_for_form(form)
    url = form.attrs["action"]
    payload = {"email": "", "_csrf_token": csrf}
    r = authenticated.post_to_page(url, data=payload)
    soup = BeautifulSoup(r.text, features="html.parser")
    # TODO: finish this.
    # Happy path sketch:
    # - get the invite info straight from Redis
    # - redeem invite
    # - log in for the first time

    # other tests to run:
    # - bad email
    # - bad csrf
    # - no csrf
