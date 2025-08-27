from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
from datetime import timedelta
import codecs
import csv
import logging
import os
import redis
import smtplib
import ssl
import uuid, string, random, json

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup
from sqlalchemy import create_engine
from talisman import Talisman
from zxcvbn import zxcvbn

from uaaextras.clients import UAAClient, UAAError, TOTPClient, CFClient
from uaaextras.validators import email_valid_for_domains
from uaaextras.validators import email_username_valid

import debugpy

debugpy.listen(("0.0.0.0", 5678))
print("waiting for debugger to attach")
debugpy.wait_for_client()
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# key = connfiguration variable to be loaded from the environment
# value = The default to use if env var is not present
CONFIG_KEYS = {
    "UAA_BASE_URL": "https://uaa.bosh-lite.com",
    "UAA_CLIENT_ID": None,
    "UAA_CLIENT_SECRET": None,
    "UAA_VERIFY_TLS": True,
    "SMTP_HOST": "localhost",
    "SMTP_PORT": 25,
    "SMTP_FROM": "no-reply@example.com",
    "SMTP_USER": None,
    "SMTP_PASS": None,
    "SMTP_CERT": None,
    "BRANDING_COMPANY_NAME": "Cloud Foundry",
    "IDP_PROVIDER_ORIGIN": "idp.com",
    "IDP_PROVIDER_URL": "https://idp.bosh-lite.com",
    "MAINTENANCE_MODE": False,
    "CF_API_URL": "https://api.bosh-lite.com",
}

UAA_INVITE_EXPIRATION_IN_SECONDS = timedelta(days=7)
FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS = 43200

PASSWORD_SPECIAL_CHARS = (
    "~",
    "@",
    "#",
    "$",
    "%",
    "^",
    "*",
    "_",
    "+",
    "=",
    "-",
    "/",
    "?",
)

redis_env = dict(host="localhost", port=6379, password="")
# Get Redis credentials
if "VCAP_SERVICES" in os.environ:
    services = json.loads(os.getenv("VCAP_SERVICES"))
    redis_info = services["aws-elasticache-redis"][0]["credentials"]

    redis_env = {
        "host": redis_info["hostname"],
        "port": int(redis_info["port"]),
        "password": redis_info["password"],
        "socket_timeout": 0.5,
        "socket_connect_timeout": 0.5,
        "ssl": True,
        "ssl_cert_reqs": None,
    }

# Connect to redis
r = redis.Redis(**redis_env)

uaadb_engine = create_engine(os.getenv("UAADB_CONNECTION_STRING", "sqlite:///:memory:"))

# Try to determine SERVER_NAME
if "VCAP_APPLICATION" in os.environ:
    cf_app_config = json.loads(os.getenv("VCAP_APPLICATION"))
    SERVER_NAME = cf_app_config["uris"][0]
    PREFERRED_URL_SCHEME = "https"
else:
    SERVER_NAME = os.environ.get("SERVER_NAME", "localhost:5000")
    PREFERRED_URL_SCHEME = "http"


def generate_temporary_password():
    """Generates a temporary password suitable for UAA"""
    passwordChars = (
        string.ascii_letters
        + string.digits
        + "".join(str(c) for c in PASSWORD_SPECIAL_CHARS)
    )
    newPassword = str(random.choice(string.ascii_letters))
    for i in range(23):
        newPassword += str(random.choice(list(passwordChars)))
    return newPassword


def generate_csrf_token():
    """Generate a secure string for use as a CSRF token"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = (
            codecs.encode(os.urandom(24), "base-64").decode("utf-8").strip()
        )

    return session["_csrf_token"]


def str_to_bool(val):
    """Convert common yes/no true/false phrases to boolean

    Args:
        val(str): The string to convert

    Returns:
        True/False: The value of the string
        None: True/False value could not be determined

    """
    val = str(val).lower()

    if val in ["1", "true", "yes", "t", "y"]:
        return True
    if val in ["0", "false", "no", "f", "n", "none", ""]:
        return False

    return None


def send_verification_code_email(app, email, invite):
    with app.app_context():
        if len(invite["failed_invites"]):
            raise RuntimeError("UAA failed to invite the user.")

        invite = invite["new_invites"][0]

        branding = {"company_name": app.config["BRANDING_COMPANY_NAME"]}

        # Lets store this invite link in Redis using the verification code
        verification_code = uuid.uuid4().hex
        verification_url = url_for(
            "redeem_invite", verification_code=verification_code, _external=True
        )

        logging.info("Invite {0}".format(invite))

        if "inviteLink" in invite:
            logging.info(
                "Success: Storing inviteLink for {0} in Redis".format(verification_code)
            )
            r.setex(
                verification_code,
                UAA_INVITE_EXPIRATION_IN_SECONDS,
                invite["inviteLink"],
            )
            # we invited them, send them the link to validate their account
            subject = render_template(
                "email/subject.txt", invite=invite, branding=branding
            ).strip()
            body = render_template(
                "email/body.html", verification_url=verification_url, branding=branding
            )

            send_email(app, email, subject, body)
            return True
        else:
            logging.info(
                "Failed: No inviteLink stored for {0}".format(verification_code)
            )
            return False


def send_email(app, email, subject, body):
    """Send an email via an external SMTP server

    Args:
        app(flask.App): The application sending the email
        email(str): The recepient of the message
        subject(str): The subject of the email
        body(str): The HTML body of the email

    Raises:
        socket.error: Could not connect to the SMTP Server

    Returns:
        True: The mail was accepted for delivery.

    """
    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["To"] = email
    msg["From"] = app.config["SMTP_FROM"]

    s = smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"])

    # if we have a cert, then trust it
    sslcontext = ssl.create_default_context()
    if app.config["SMTP_CERT"] is not None:
        sslcontext.load_verify_locations(cadata=app.config["SMTP_CERT"])
    s.starttls(context=sslcontext)

    # if smtp credentials were provided, login
    if app.config["SMTP_USER"] is not None and app.config["SMTP_PASS"] is not None:
        s.login(app.config["SMTP_USER"], app.config["SMTP_PASS"])

    s.sendmail(app.config["SMTP_FROM"], [email], msg.as_string())
    s.quit()

    return True


def create_app(env=os.environ):
    """Create an instance of the web application"""
    # setup our app config
    app = Flask(__name__)
    # use the supplied secret key, or make one up
    app.secret_key = os.environ.get(
        "FLASK_SECRET_KEY",
        codecs.encode(os.urandom(24), "base-64").decode("utf-8").strip(),
    )
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    if env.get("ENV") == "production":
        csp = {
            "default-src": "'self'",
            "script-src": "'self'",
            "connect-src": "'self'",
            "object-src": "'self'",
            "frame-ancestors": "'self'",
            "img-src": ["'self'", "*.cloud.gov"],
            "style-src": ["'self'", "*.cloud.gov", "*.googleapis.com"],
            "font-src": ["'self'", "fonts.gstatic.com", "*.cloud.gov"],
            "form-action": ["'self'", "*.cloud.gov"],
        }
        Talisman(app, content_security_policy=csp)

    @app.after_request
    def set_headers(response):
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
        response.cache_control.private = True
        response.headers["Pragma"] = "no-cache"
        return response

    # copy these environment variables into app.config
    for ck, default in CONFIG_KEYS.items():
        app.config[ck] = env.get(ck, default)

    # Assume we're running under TLS
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    # do boolean checks on this variable
    app.config["UAA_VERIFY_TLS"] = str_to_bool(app.config["UAA_VERIFY_TLS"])

    # make sure our base url doesn't have a trailing slash as UAA will flip out
    app.config["UAA_BASE_URL"] = app.config["UAA_BASE_URL"].rstrip("/")

    app.config["APP_ROOT"] = os.path.dirname(os.path.abspath(__file__))
    app.config["APP_STATIC"] = os.path.join(app.config["APP_ROOT"], "static")

    # Load valid list of .gov domains
    # download current-federal.csv from
    #   https://raw.githubusercontent.com/GSA/data/master/dotgov-domains/current-federal.csv
    # and place into 'static' dir
    domain_list = ["mil", "si.edu"]
    csv_path = os.path.join(app.config["APP_STATIC"], "current-federal.csv")
    with open(csv_path, newline="", encoding="utf-8") as fed_gov_csv:
        for row in csv.reader(fed_gov_csv):
            domain_list.append(row[0].strip().rstrip().lower())
    app.config["VALID_FED_DOMAINS"] = tuple(domain_list)

    logging.info("Loaded application configuration:")
    if app.config.get("DEBUG"):
        for ck in sorted(CONFIG_KEYS.keys()):
            logging.info("{0}: {1}".format(ck, app.config[ck]))

    @app.before_request
    def check_maintenance_mode():
        """
        Before each request, check to see if we're in maintenance mode.

        If we are, redirect all requests to the maintenance page to ensure users
        don't try and perform any actions that the system will not support while
        services are unavailable.
        """

        if app.config["MAINTENANCE_MODE"]:
            logging.warning("UAA Extras is currently in maintenance mode.")
            return render_template("maintenance.html"), 200

    @app.before_request
    def have_uaa_and_csrf_token():
        """Before each request, make sure we have a valid token from UAA.

        If we don't send them to UAA to start the oauth process.

        Technically we should bounce them through the renew token process if we already have one,
        but this app will be used sparingly, so it's fine to push them back through the authorize flow
        each time we need to renew our token.

        """
        # don't authenticate the oauth code receiver, or we'll never get the code back from UAA
        if request.endpoint and request.endpoint in [
            "oauth_login",
            "forgot_password",
            "redeem_invite",
            "reset_password",
            "signup",
            "static",
            "logout",
        ]:
            return

        # check our token, and expirary date
        token = session.get("UAA_TOKEN", None)

        token_checking_client = UAAClient(
            app.config["UAA_BASE_URL"],
            None,
            verify_tls=app.config["UAA_VERIFY_TLS"],
        )

        has_valid_token = False

        # if all looks good, setup the client
        if token:
            g.uaac = UAAClient(
                app.config["UAA_BASE_URL"],
                token,
                verify_tls=app.config["UAA_VERIFY_TLS"],
            )
            has_valid_token = g.uaac.check_token_valid(
                token, app.config["UAA_CLIENT_ID"], app.config["UAA_CLIENT_SECRET"]
            )

        if not has_valid_token:
            # if not forget the token, it's bad (if we have one)
            session.clear()
            session["_endpoint"] = request.endpoint

            return redirect(
                "{0}/oauth/authorize?client_id={1}&response_type=code".format(
                    app.config["UAA_BASE_URL"], app.config["UAA_CLIENT_ID"]
                )
            )

        g.totp = TOTPClient(uaadb_engine)
        # if it's a POST request, that's not to oauth_login
        # Then check for a CSRF token, if we don't have one, bail
        if request.method == "POST":
            csrf_token = session.pop("_csrf_token", None)
            if not csrf_token or csrf_token != request.form.get("_csrf_token"):
                logging.error(
                    "Error validating CSRF token.  Got: {0}; Expected: {1}".format(
                        request.form.get("_csrf_token"), csrf_token
                    )
                )

                return render_template("error/csrf.html"), 400

    @app.route("/oauth/login")
    def oauth_login():
        """Called at the end of the oauth flow.  We'll receive an auth code from UAA and use it to
        retrieve a bearer token that we can use to actually do stuff
        """
        logging.info(request.referrer)
        is_invitation = (
            request.referrer and request.referrer.find("invitations/accept") != 1
        )
        print("=============== ===============")
        print(f"=============== request is: {request} ===============")
        print("about to call first_login")
        if is_invitation and "code" not in request.args:
            return redirect(url_for("first_login"))

        try:
            # connect a client with no token
            uaac = UAAClient(
                app.config["UAA_BASE_URL"],
                None,
                verify_tls=app.config["UAA_VERIFY_TLS"],
            )

            # auth with our client secret and the code they gave us
            token = uaac.oauth_token(
                request.args["code"],
                app.config["UAA_CLIENT_ID"],
                app.config["UAA_CLIENT_SECRET"],
            )

            # if it's valid, but missing the scope we need, bail
            if "scim.invite" not in token["scope"].split(" "):
                raise RuntimeError(
                    "Valid oauth authentication but missing the scim.invite scope.  Scopes: {0}".format(
                        token["scope"]
                    )
                )

            # make flask expire our session for us, by expiring it shortly before the token expires
            session.permanent = True
            app.permanent_session_lifetime = timedelta(seconds=token["expires_in"] - 30)

            # stash the stuff we care about
            session["UAA_TOKEN"] = token["access_token"]
            session["UAA_TOKEN_SCOPES"] = token["scope"].split(" ")
            if is_invitation:
                return redirect(url_for("first_login"))
            endpoint = session.pop("_endpoint", None)
            if not endpoint:
                endpoint = "index"
            logging.info(endpoint)
            return redirect(url_for(endpoint))
        except UAAError:
            logging.exception("An invalid authorization_code was received from UAA")
            return render_template("error/token_validation.html"), 401
        except RuntimeError:
            logging.exception("Token validated but had wrong scope")
            return render_template("error/missing_scope.html"), 403

    @app.route("/", methods=["GET", "POST"])
    def index():
        return render_template("index.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        # start with giving them the form
        if request.method == "GET":
            return render_template("signup.html")

        # if we've reached here we are POST, and they've asked us to invite

        # validate the email address
        email = request.form.get("email", "").strip().rstrip()
        if not email:
            flash("Email cannot be blank.")
            return render_template("signup.html")
        try:
            v = validate_email(email)  # validate and get info
            email = v["email"]  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template("signup.html")

        # Check the username pattern is valid, a-z, numbers and a select set of special characters
        if not email_username_valid(email):
            flash(
                "This does not seem to be a valid username for U.S. federal government email addresses. "
                "Self-service invitations are only offered for U.S. federal government email addresses. "
                "If you do have a valid U.S. federal government email address, email us at "
                "cloud-gov-inquiries@gsa.gov to let us know to whitelist your email address."
            )
            return render_template("signup.html")

        # Check for feds here
        if not email_valid_for_domains(email, app.config["VALID_FED_DOMAINS"]):
            flash(
                "This does not seem to be a U.S. federal government email address. "
                "Self-service invitations are only offered for U.S. federal government email addresses. "
                "If you do have a U.S. federal government email address, email us at "
                "cloud-gov-inquiries@gsa.gov to let us know to whitelist your domain."
            )
            return render_template("signup.html")

        # email is good, lets invite them
        try:
            if not getattr(g, "uaac", False):
                g.uaac = UAAClient(
                    app.config["UAA_BASE_URL"],
                    None,
                    verify_tls=app.config["UAA_VERIFY_TLS"],
                )
            if g.uaac.does_origin_user_exist(
                app.config["UAA_CLIENT_ID"],
                app.config["UAA_CLIENT_SECRET"],
                email,
                app.config["IDP_PROVIDER_ORIGIN"],
            ):
                flash("You already have a valid account.")
                return render_template("signup.html")

            redirect_uri = os.path.join(request.url_root, "oauth", "login")
            logging.info("redirect for invite: {0}".format(redirect_uri))
            invite = g.uaac.client_invite_users(
                app.config["UAA_CLIENT_ID"],
                app.config["UAA_CLIENT_SECRET"],
                email,
                redirect_uri,
            )

            if send_verification_code_email(app, email, invite):
                return render_template("signup_invite_sent.html")

        except UAAError as exc:
            # if UAA complains that our access token is invalid then force them back through the login
            # process.
            # TODO: Fix this properly by implementing the refresh token oauth flow
            # in the UAAClient when it detects it's token is no longer valid
            if "Invalid access token" in str(exc):
                return redirect(url_for("logout"))
            else:
                logging.exception("An error occured communicating with UAA")
        except Exception:
            logging.exception("An error occured during the invite process")

        return render_template("error/internal.html"), 500

    @app.route("/invite", methods=["GET", "POST"])
    def invite():
        # start with giving them the form
        if request.method == "GET":
            return render_template("invite.html")

        # if we've reached here we are POST, and they've asked us to invite

        # check our token, and expirary date
        token = session.get("UAA_TOKEN", None)

        try:
            decoded_token = g.uaac.decode_access_token(token)
        except:
            logging.exception("An invalid access token was decoded")
            return render_template("error/token_validation.html"), 401

        user_id = decoded_token["user_id"]

        # check for org_manager role
        cf_client = CFClient(app.config["CF_API_URL"], token)
        if not cf_client.is_org_manager(cf_client._get_cf_client(), user_id):
            logging.info("non-org-manager attempted user invite")
            flash(
                Markup(
                    'Only organization managers can invite users. See our documentation <a href="https://cloud.gov/docs/orgs-spaces/new-org/#org-manager-email">here</a>'
                )
            )
            return render_template("invite.html")

        # validate the email address
        email = request.form.get("email", "")
        if not email:
            flash("Email cannot be blank.")
            return render_template("invite.html")
        try:
            v = validate_email(email)  # validate and get info
            email = v.normalized  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template("invite.html")

        # email is good, lets invite them
        try:
            if g.uaac.does_origin_user_exist(
                app.config["UAA_CLIENT_ID"],
                app.config["UAA_CLIENT_SECRET"],
                email,
                app.config["IDP_PROVIDER_ORIGIN"],
            ):
                flash("User already has a valid account.")
                return render_template("invite.html")

            redirect_uri = os.path.join(request.url_root, "oauth", "login")
            logging.info("redirect for invite: {0}".format(redirect_uri))
            invite = g.uaac.invite_users(email, redirect_uri)

            if send_verification_code_email(app, email, invite):
                return render_template("invite_sent.html")

        except UAAError as exc:
            # if UAA complains that our access token is invalid then force them back through the login
            # process.
            # TODO: Fix this properly by implementing the refresh token oauth flow
            # in the UAAClient when it detects it's token is no longer valid
            if "Invalid access token" in str(exc):
                return redirect(url_for("logout"))
            else:
                logging.exception("An error occured communicating with UAA")
        except Exception:
            logging.exception("An error occured during the invite process")

        return render_template("error/internal.html"), 500

    @app.route("/redeem-invite", methods=["GET", "POST"])
    def redeem_invite():
        # Make sure that the requested URL has validation_token,
        # otherwise redirect to error page.
        if "verification_code" not in request.args:
            logging.info("The invitation link was missing a validation code.")
            return render_template("error/token_validation.html"), 401

        # Store the validation token to check for UAA invite link
        verification_code = request.args.get("verification_code")

        # Check if Redis key was previously requested, otherwise load the UAA invite
        try:
            invite = r.get(verification_code)
        except redis.exceptions.RedisError:
            logging.exception("The UAA link was not accessible because Redis is down.")
            return render_template("error/internal.html"), 500
        if invite is None:
            logging.info("UAA invite link is expired. {0}".format(verification_code))
            return render_template("error/token_validation.html"), 401

        else:
            invite_url = bytes.decode(invite)
            logging.info("Accessed UAA invite link. {0}".format(verification_code))

            if request.method == "GET":
                redeem_link = url_for(
                    "redeem_invite", verification_code=verification_code, _external=True
                )
                return render_template("redeem-confirm.html", redeem_link=redeem_link)

            if request.method == "POST":
                return redirect(invite_url, code=302)

    @app.route("/first-login", methods=["GET"])
    def first_login():
        # check our token, and expirary date
        token = session.get("UAA_TOKEN", None)

        try:
            decoded_token = g.uaac.decode_access_token(token)
        except:
            logging.exception("An invalid access token was decoded")
            return render_template("error/token_validation.html"), 401

        user = g.uaac.get_user(decoded_token["user_id"])
        print(f"=== user in first login: {user} ===")
        logging.info("USER: {0}".format(user))
        if user["origin"] == "uaa":
            user["origin"] = app.config["IDP_PROVIDER_ORIGIN"]
            user["externalId"] = user["userName"]
            g.uaac.put_user(user)
        if user["origin"] == app.config["IDP_PROVIDER_ORIGIN"]:
            return redirect(app.config["IDP_PROVIDER_URL"])
        else:
            return redirect(app.config["UAA_BASE_URL"])

    @app.route("/change-password", methods=["GET", "POST"])
    def change_password():
        # start with giving them the form
        if request.method == "GET":
            return render_template("change_password.html")

        # if we've reached here we are POST so change the pass

        # check our token, and expirary date
        token = session.get("UAA_TOKEN", None)

        try:
            decoded_token = g.uaac.decode_access_token(token)
        except:
            logging.exception("An invalid access token was decoded")
            return render_template("error/token_validation.html"), 401

        # validate new password
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        repeat_password = request.form.get("repeat_password", "")
        errors = []
        if old_password == new_password or old_password == repeat_password:
            errors.append("Your new password cannot match your old password.")
        if not old_password:
            errors.append("Your old password cannot be blank.")
        if not new_password:
            errors.append("Your new password cannot be blank.")
        if not repeat_password:
            errors.append("You must repeat your new password.")
        if new_password != repeat_password:
            errors.append("Your new password does not match your repeated password.")

        # Get some userinfo to include in the zxcvbn check.
        # The info includes their email address, the IDP_PROVIDER_ORIGIN, and
        # their email address split at the '@' symbol.
        username = g.uaac.get_user(decoded_token["user_id"])["userName"]
        userinfo = [username, app.config["IDP_PROVIDER_ORIGIN"], old_password]
        print(f"app config is: {app.config}")
        print(f"userInfo: {userinfo}")
        for part in username.split("@"):
            userinfo.append(part)

        result = zxcvbn(new_password, user_inputs=userinfo)

        if result["score"] < 3:
            errors.append(result["feedback"]["warning"])

        if len(errors) != 0:
            for error in errors:
                flash(error)
            return render_template("change_password.html")

        try:
            g.uaac.change_password(decoded_token["user_id"], old_password, new_password)
            return render_template("password_changed.html")
        except UAAError as exc:
            for error in str(exc).split(","):
                flash(error)
            return render_template("change_password.html")
        except Exception:
            logging.exception("Error changing password")

        return render_template("error/internal.html"), 500

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        identity_token = uuid.uuid4().hex

        # start with giving them the form
        if request.method == "GET":
            return render_template("forgot_password.html")

        # if we've reached here we are POST so we can email user link
        email = request.form.get("email_address", "")
        if not email:
            flash("Email cannot be blank.")
            return render_template("forgot_password.html")
        try:
            v = validate_email(email)  # validate and get info
            email = v.normalized  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template("forgot_password.html")

        # If we've made it this far, it's a valid email so we'll generate and store a
        # token and send an email.
        logging.info("generating validation token for user")

        branding = {"company_name": app.config["BRANDING_COMPANY_NAME"]}

        reset = {
            "verifyLink": url_for(
                "reset_password", validation=identity_token, _external=True
            )
        }
        logging.info(reset["verifyLink"])

        password = {"changeLink": changeLink}

        subject = render_template(
            "email/subject-password.txt", reset=reset, branding=branding
        ).strip()
        body = render_template(
            "email/body-password.html",
            reset=reset,
            branding=branding,
            password=password,
        )

        uaac = UAAClient(
            app.config["UAA_BASE_URL"], None, verify_tls=app.config["UAA_VERIFY_TLS"]
        )

        user_exists = uaac.does_origin_user_exist(
            app.config["UAA_CLIENT_ID"],
            app.config["UAA_CLIENT_SECRET"],
            email,
            app.config["IDP_PROVIDER_ORIGIN"],
        )

        if user_exists:
            try:
                r.setex(email, FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS, identity_token)
            except redis.exceptions.RedisError:
                return render_template("error/internal.html"), 500

            send_email(app, email, subject, body)
        else:
            logging.info(
                "{} does not exist. Forgot password email not sent".format(email)
            )

        return render_template("forgot_password.html", email_sent=True, email=email)

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        # start with giving them the form
        if request.method == "GET":
            if "validation" not in request.args:
                flash(
                    "The password validation link is incomplete. Please verify your link is correct and try again."
                )
                return render_template("reset_password.html", validation_code=None)

            return render_template(
                "reset_password.html", validation_code=request.args["validation"]
            )

        # if we've reached here we are POST so we can email user link
        token = request.form.get("_validation_code", "")
        email = request.form.get("email_address", "")
        if not email:
            flash("Email cannot be blank.")
            return render_template("reset_password.html")
        try:
            v = validate_email(email)  # validate and get info
            email = v.normalized  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template("reset_password.html")

        # If we've made it this far, it's a valid email so let's verify the generated
        # token with their email address.
        try:
            userToken = r.get(email)
        except redis.exceptions.RedisError:
            return render_template("error/internal.html"), 500

        if userToken is not None and userToken.decode("utf-8") == token:
            logging.info(
                "Successfully verified token {0} for {1}".format(userToken, email)
            )
            try:
                r.delete(email)
            except redis.exceptions.RedisError:
                return render_template("error/internal.html"), 500
        else:
            flash(
                "Valid token not found. Please try your forgot password request again."
            )
            return render_template("reset_password.html")

        temporaryPassword = generate_temporary_password()
        try:
            g.uaac = UAAClient(
                app.config["UAA_BASE_URL"],
                None,
                verify_tls=app.config["UAA_VERIFY_TLS"],
            )
            if g.uaac.set_temporary_password(
                app.config["UAA_CLIENT_ID"],
                app.config["UAA_CLIENT_SECRET"],
                email,
                temporaryPassword,
            ):
                logging.info("Set temporary password for {0}".format(email))
                return render_template(
                    "reset_password.html",
                    password=temporaryPassword,
                    loginLink=app.config["UAA_BASE_URL"],
                )
            else:
                flash(
                    "Unable to set temporary password. Did you use the right email address?"
                )
                return render_template("reset_password.html")
        except Exception:
            logging.exception("Unable to set your temporary password.")

    @app.route("/reset-totp", methods=["GET", "POST"])
    def reset_totp():
        token = session.get("UAA_TOKEN", None)
        try:
            decoded_token = g.uaac.decode_access_token(token)
            user = g.uaac.get_user(decoded_token["user_id"])
        except:
            return redirect(app.config["UAA_BASE_URL"])

        if user["origin"] != app.config["IDP_PROVIDER_ORIGIN"]:
            return redirect(url_for("index"))

        if request.method == "GET":
            return render_template("reset_totp.html")

        username = user["userName"]
        g.totp.unset_totp_seed(username)
        g.uaac.invalidate_tokens(decoded_token["user_id"])
        session.clear()
        return redirect(app.config["UAA_BASE_URL"] + "/logout.do")

    @app.route("/logout")
    def logout():
        session.clear()

        return redirect(url_for("index"))

    app.config["SERVER_NAME"] = SERVER_NAME
    app.config["PREFERRED_URL_SCHEME"] = PREFERRED_URL_SCHEME

    with app.app_context():
        changeLink = url_for("change_password", _external=True)

    return app
