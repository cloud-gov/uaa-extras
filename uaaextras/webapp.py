from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
import codecs
import logging
import os
import smtplib
import redis
import uuid

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from talisman import Talisman

from uaaextras.clients import UAAClient, UAAError

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# key = connfiguration variable to be loaded from the environment
# value = The default to use if env var is not present
CONFIG_KEYS = {
    'UAA_BASE_URL': 'https://uaa.bosh-lite.com',
    'UAA_CLIENT_ID': None,
    'UAA_CLIENT_SECRET': None,
    'UAA_VERIFY_TLS': True,
    'SMTP_HOST': 'localhost',
    'SMTP_PORT': 25,
    'SMTP_FROM': 'no-reply@example.com',
    'SMTP_USER': None,
    'SMTP_PASS': None,
    'BRANDING_COMPANY_NAME': 'Cloud Foundry',
    'IDP_PROVIDER_ORIGIN': 'https://idp.bosh-lite.com',
    'IDP_PROVIDER_URL': 'my.idp.com',
    'ACCOUNTS_BASE_URL': 'https://accounts.bosh-lite.com'
}


def generate_csrf_token():
    """Generate a secure string for use as a CSRF token"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = codecs.encode(os.urandom(24), 'base-64').decode('utf-8').strip()

    return session['_csrf_token']


def str_to_bool(val):
    """Convert common yes/no true/false phrases to boolean

    Args:
        val(str): The string to convert

    Returns:
        True/False: The value of the string
        None: True/False value could not be determined

    """
    val = str(val).lower()

    if val in ['1', 'true', 'yes', 't', 'y']:
        return True
    if val in ['0', 'false', 'no', 'f', 'n', 'none', '']:
        return False

    return None


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
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['To'] = email
    msg['From'] = app.config['SMTP_FROM']

    s = smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT'])
    s.set_debuglevel(1)

    # if smtp credentials were provided, login
    if app.config['SMTP_USER'] is not None and app.config['SMTP_PASS'] is not None:
        s.login(app.config['SMTP_USER'], app.config['SMTP_PASS'])

    s.sendmail(app.config['SMTP_FROM'], [email], msg.as_string())
    s.quit()

    return True


def create_app(env=os.environ):
    """Create an instance of the web application"""
    # setup our app config
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY")
    app.jinja_env.globals['csrf_token'] = generate_csrf_token

    if env.get('ENV') == 'production':
        csp = {
            'default-src': '\'self\'',
            'img-src': '*',
            'style-src': [
                '\'self\'',
                '*.cloud.gov',
                '*.googleapis.com',
                '\'unsafe-inline\''
            ],
            'font-src': [
                '\'self\'',
                'fonts.gstatic.com',
                '*.cloud.gov'
            ]
        }
        Talisman(app, content_security_policy=csp)

    @app.after_request
    def set_headers(response):
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
        response.cache_control.private = True
        response.headers['Pragma'] = 'no-cache'
        return response

    # copy these environment variables into app.config
    for ck, default in CONFIG_KEYS.items():
        app.config[ck] = env.get(ck, default)

    # do boolean checks on this variable
    app.config['UAA_VERIFY_TLS'] = str_to_bool(app.config['UAA_VERIFY_TLS'])

    # make sure our base url doesn't have a trailing slash as UAA will flip out
    app.config['UAA_BASE_URL'] = app.config['UAA_BASE_URL'].rstrip('/')

    logging.info('Loaded application configuration:')
    for ck in sorted(CONFIG_KEYS.keys()):
        logging.info('{0}: {1}'.format(ck, app.config[ck]))

    @app.before_request
    def have_uaa_and_csrf_token():
        """Before each request, make sure we have a valid token from UAA.

        If we don't send them to UAA to start the oauth process.

        Technically we should bounce them through the renew token process if we already have one,
        but this app will be used sparingly, so it's fine to push them back through the authorize flow
        each time we need to renew our token.

        """
        # don't authenticate the oauth code receiver, or we'll never get the code back from UAA
        if request.endpoint and request.endpoint in ['oauth_login', 'forgot_password', 'reset_password', 'static']:
            return

        # check our token, and expirary date
        token = session.get('UAA_TOKEN', None)

        # if all looks good, setup the client
        if token:
            g.uaac = UAAClient(
                app.config['UAA_BASE_URL'],
                session['UAA_TOKEN'],
                verify_tls=app.config['UAA_VERIFY_TLS']
            )
        else:
            # if not forget the token, it's bad (if we have one)
            session.clear()
            session['_endpoint'] = request.endpoint

            return redirect('{0}/oauth/authorize?client_id={1}&response_type=code'.format(
                app.config['UAA_BASE_URL'],
                app.config['UAA_CLIENT_ID']
            ))

        # if it's a POST request, that's not to oauth_login
        # Then check for a CSRF token, if we don't have one, bail
        if request.method == "POST":
            csrf_token = session.pop('_csrf_token', None)
            if not csrf_token or csrf_token != request.form.get('_csrf_token'):
                logging.error('Error validating CSRF token.  Got: {0}; Expected: {1}'.format(
                    request.form.get('_csrf_token'),
                    csrf_token
                ))

                return render_template('error/csrf.html'), 400

    @app.route('/oauth/login')
    def oauth_login():
        """Called at the end of the oauth flow.  We'll receive an auth code from UAA and use it to
        retrieve a bearer token that we can use to actually do stuff
        """
        logging.info(request.referrer)
        is_invitation = request.referrer and request.referrer.find('invitations/accept') != 1
        if is_invitation and 'code' not in request.args:
            return redirect(url_for('first_login'))

        try:

            # connect a client with no token
            uaac = UAAClient(app.config['UAA_BASE_URL'], None, verify_tls=app.config['UAA_VERIFY_TLS'])

            # auth with our client secret and the code they gave us
            token = uaac.oauth_token(request.args['code'], app.config['UAA_CLIENT_ID'], app.config['UAA_CLIENT_SECRET'])

            # if it's valid, but missing the scope we need, bail
            if 'scim.invite' not in token['scope'].split(' '):
                raise RuntimeError('Valid oauth authentication but missing the scim.invite scope.  Scopes: {0}'.format(
                    token['scope']
                ))

            # make flask expire our session for us, by expiring it shortly before the token expires
            session.permanent = True
            app.permanent_session_lifetime = token['expires_in'] - 30

            # stash the stuff we care about
            session['UAA_TOKEN'] = token['access_token']
            session['UAA_TOKEN_SCOPES'] = token['scope'].split(' ')
            if is_invitation:
                return redirect(url_for('first_login'))
            endpoint = session.pop('_endpoint', None)
            if not endpoint:
                endpoint = 'index'
            logging.info(endpoint)
            return redirect(url_for(endpoint))
        except UAAError:
            logging.exception('An invalid authorization_code was received from UAA')
            return render_template('error/token_validation.html'), 401
        except RuntimeError:
            logging.exception('Token validated but had wrong scope')
            return render_template('error/missing_scope.html'), 403

    @app.route('/', methods=['GET', 'POST'])
    def index():
        return render_template('index.html')

    @app.route('/invite', methods=['GET', 'POST'])
    def invite():
        # start with giving them the form
        if request.method == 'GET':
            return render_template('invite.html')

        # if we've reached here we are POST, and they've asked us to invite

        # validate the email address
        email = request.form.get('email', '')
        if not email:
            flash('Email cannot be blank.')
            return render_template('invite.html')
        try:
            v = validate_email(email)  # validate and get info
            email = v["email"]  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template('invite.html')

        # email is good, lets invite them
        try:
            redirect_uri = os.path.join(request.url_root, 'oauth', 'login')
            logging.info('redirect for invite: {0}'.format(redirect_uri))
            invite = g.uaac.invite_users(email, redirect_uri)

            if len(invite['failed_invites']):
                raise RuntimeError('UAA failed to invite the user.')

            invite = invite['new_invites'][0]

            branding = {
                'company_name': app.config['BRANDING_COMPANY_NAME']
            }

            # we invited them, send them the link to validate their account
            subject = render_template('email/subject.txt', invite=invite, branding=branding).strip()
            body = render_template('email/body.html', invite=invite, branding=branding)

            send_email(app, email, subject, body)
            return render_template('invite_sent.html')
        except UAAError as exc:
            # if UAA complains that our access token is invalid then force them back through the login
            # process.
            # TODO: Fix this properly by implementing the refresh token oauth flow
            # in the UAAClient when it detects it's token is no longer valid
            if 'Invalid access token' in str(exc):
                return redirect(url_for('logout'))
            else:
                logging.exception('An error occured communicating with UAA')
        except Exception:
            logging.exception('An error occured during the invite process')

        return render_template('error/internal.html'), 500

    @app.route('/first-login', methods=['GET'])
    def first_login():

        # check our token, and expirary date
        token = session.get('UAA_TOKEN', None)

        try:
            decoded_token = g.uaac.decode_access_token(token)
        except:
            logging.exception('An invalid access token was decoded')
            return render_template('error/token_validation.html'), 401

        user = g.uaac.get_user(decoded_token['user_id'])
        logging.info('USER: {0}'.format(user))
        if user['origin'] == 'uaa':
            user['origin'] = app.config['IDP_PROVIDER_ORIGIN']
            user['externalId'] = user['userName']
            g.uaac.put_user(user)
            return redirect(app.config['IDP_PROVIDER_URL'])
        else:
            return redirect(app.config['UAA_BASE_URL'])

    @app.route('/change-password', methods=['GET', 'POST'])
    def change_password():
        # start with giving them the form
        if request.method == 'GET':
            return render_template('change_password.html')

        # if we've reached here we are POST so change the pass

        # validate new password
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        repeat_password = request.form.get('repeat_password', '')
        errors = []
        if not old_password:
            errors.append('Your old password cannot be blank.')
        if not new_password:
            errors.append('Your new password cannot be blank.')
        if not repeat_password:
            errors.append('You must repeat your new password.')
        if new_password != repeat_password:
            errors.append('Your new password does not match your repeated password.')

        if len(errors) != 0:
            for error in errors:
                flash(error)
            return render_template('change_password.html')

        # check our token, and expirary date
        token = session.get('UAA_TOKEN', None)

        try:
            decoded_token = g.uaac.decode_access_token(token)
        except:
            logging.exception('An invalid access token was decoded')
            return render_template('error/token_validation.html'), 401

        try:
            g.uaac.change_password(decoded_token['user_id'], old_password, new_password)
        except:
            logging.exception('Error changing password')

        return render_template('password_changed.html')

    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        EXPIRATION_TIME = 43200
        IDENTITY_TOKEN = uuid.uuid4().hex
        r = redis.StrictRedis(host='localhost', port=6379, db=0)

        # start with giving them the form
        if request.method == 'GET':
            return render_template('forgot_password.html')

        # if we've reached here we are POST so we can email user link
        email = request.form.get('email_address', '')
        if not email:
            flash('Email cannot be blank.')
            return render_template('forgot_password.html')
        try:
            v = validate_email(email)  # validate and get info
            email = v["email"]  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template('forgot_password.html')

        # If we've made it this far, it's a valid email so we'll generate and store a
        # token and send an email.
        logging.info('generating validation token for user')

        branding = {
            'company_name': app.config['BRANDING_COMPANY_NAME']
        }

        reset = {
            'verifyLink': '{0}/reset-password?validation={1}'.format(app.config['ACCOUNTS_BASE_URL'], IDENTITY_TOKEN)
        }
        logging.info(reset['verifyLink'])

        subject = render_template('email/subject-password.txt', reset=reset, branding=branding).strip()
        body = render_template('email/body-password.html', reset=reset, branding=branding)
        # send_email(app, email, subject, body)
        r.setex(email, EXPIRATION_TIME, IDENTITY_TOKEN)

        return render_template('forgot_password.html', email_sent=True, email=email)

    @app.route('/reset-password', methods=['GET', 'POST'])
    def reset_password():

        r = redis.StrictRedis(host='localhost', port=6379, db=0)
        validation_code = False

        # start with giving them the form
        if request.method == 'GET':
            try:
                validation_code = request.args['validation']
            except:
                flash('The password validation link is incomplete. Please verify your link is correct and try again.')
                return render_template('reset_password.html')

            return render_template('reset_password.html', validation_code=validation_code)

        # if we've reached here we are POST so we can email user link
        token = request.form.get('_validation_code', '')
        email = request.form.get('email_address', '')
        if not email:
            flash('Email cannot be blank.')
            return render_template('reset_password.html')
        try:
            v = validate_email(email)  # validate and get info
            email = v["email"]  # replace with normalized form
        except EmailNotValidError as exc:
            # email is not valid, exception message is human-readable
            flash(str(exc))
            return render_template('reset_password.html')

        # If we've made it this far, it's a valid email so let's verify the generated
        # token with their email address.
        userToken = r.get(email)

        if userToken == None:
            flash('Token has expired. Please try your forgot password request again.')
            return render_template('reset_password.html')
        elif userToken.decode('utf-8') == token:
            logging.info('Successfully verified email {0}'.format(userToken))
            r.delete(email)

        temporaryPassword = codecs.encode(os.urandom(24), 'base-64').decode('utf-8').strip()

        return render_template('reset_password.html', password=temporaryPassword)

    @app.route('/logout')
    def logout():
        session.clear()

        return redirect(url_for('index'))

    return app
