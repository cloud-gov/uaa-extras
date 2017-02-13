from datetime import timedelta
import csv
import codecs
import json
import logging
import os
import uuid

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

from redis import StrictRedis
from talisman import Talisman

from uaaextras.clients import UAAClient, UAAError
from uaaextras.email import Emailer, EmailNotValidError, InvalidDomainError
from uaaextras.utils import str_to_bool, generate_password

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
    'IDP_PROVIDER_ORIGIN': 'idp.com',
    'IDP_PROVIDER_URL': 'https://idp.bosh-lite.com',
    'PW_EXPIRES_DAYS': 90,
    'PW_EXPIRATION_WARN_DAYS': 10,
    'UAA_INVITE_EXPIRATION_IN_SECONDS': timedelta(days=7),
    'FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS': 43200,
    'VALID_DOMAIN_LIST': 'current-federal.csv'
}


def generate_csrf_token():
    """Generate a secure string for use as a CSRF token"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = codecs.encode(os.urandom(24), 'base-64').decode('utf-8').strip()

    return session['_csrf_token']


app = Flask(__name__)
app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.after_request
def set_headers(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    response.cache_control.private = True
    response.headers['Pragma'] = 'no-cache'
    return response


@app.before_request
def uaac():
    """Configure our UAA client with client credentials"""
    g.uaac = UAAClient(
        app.config['UAA_BASE_URL'],
        app.config['UAA_CLIENT_ID'],
        app.config['UAA_CLIENT_SECRET'],
        verify_tls=app.config['UAA_VERIFY_TLS']
    )


@app.before_request
def connect_redis():
    try:
        g.redis = StrictRedis(**app.config['REDIS_PARAMS'])
        g.redis.ping()
    except Exception as exc:
        logging.critical('Unable to connect to Redis: {0}'.format(exc))
        return render_template('error/internal.html'), 500


@app.before_request
def setup_email():
    g.emailer = Emailer(
        app.config['SMTP_FROM'],
        app.config['SMTP_HOST'],
        app.config['SMTP_PORT'],
        app.config['SMTP_USER'],
        app.config['SMTP_PASS'],
        valid_domains=app.config['VALID_DOMAINS']
    )


@app.before_request
def have_uaa_and_csrf_token():
    """Before each request, make sure we have a valid token from UAA.

    If we don't send them to UAA to start the oauth process.

    Technically we should bounce them through the renew token process if we already have one,
    but this app will be used sparingly, so it's fine to push them back through the authorize flow
    each time we need to renew our token.

    """

    # these pages don't require authentication
    SKIP_AUTH = ['/oauth/login', '/signup', '/forgot-password', '/reset-password', '/redeem-invite', '/static']

    # these pages don't require CSRF for posts
    SKIP_CSRF = ['/oauth/login']

    # if it's a POST request, then check for a CSRF token, if we don't have one, bail
    if request.method == "POST" and request.url_rule.rule not in SKIP_CSRF:
        csrf_token = session.pop('_csrf_token', None)
        if not csrf_token or csrf_token != request.form.get('_csrf_token'):
            logging.error('Error validating CSRF token.  Got: {0}; Expected: {1}'.format(
                request.form.get('_csrf_token'),
                csrf_token
            ))

            return render_template('error/csrf.html'), 400

    if request.url_rule.rule in SKIP_AUTH:
        return

    # if we are here then we need to make sure we have a valid session with a token
    # as we need to be authenticated
    token = session.get('UAA_TOKEN', None)

    if not token or not g.uaac.set_user_token(token):
        # if not forget the token, it's bad (if we have one)
        session.clear()
        session['_endpoint'] = request.endpoint

        return redirect('{0}/oauth/authorize?client_id={1}&response_type=code'.format(
            app.config['UAA_BASE_URL'],
            app.config['UAA_CLIENT_ID']
        ))


@app.route('/oauth/login')
def oauth_login():
    """Called at the end of the oauth flow.  We'll receive an auth code from UAA and use it to
    retrieve a bearer token that we can use to actually do stuff
    """
    try:

        # auth with our client secret and the code they gave us
        token = g.uaac.oauth_token(request.args['code'])

        # if it's valid, but missing the scope we need, bail
        if 'scim.invite' not in token['scope'].split(' '):
            raise RuntimeError('Valid oauth authentication but missing the scim.invite scope.  Scopes: {0}'.format(
                token['scope']
            ))

        # make flask expire our session for us, by expiring it shortly before the token expires
        session.permanent = True
        app.permanent_session_lifetime = timedelta(seconds=token['expires_in'] - 30)

        # stash the stuff we care about
        session['UAA_TOKEN'] = token['access_token']
        session['UAA_TOKEN_SCOPES'] = token['scope'].split(' ')

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


@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')


@app.route('/invite', methods=['GET'])
def invite():
    return render_template('invite.html')


@app.route('/invite', methods=['POST'])
@app.route('/signup', methods=['POST'])
def process_invite():

    if 'signup' in request.url_rule.rule:
        template = 'signup'
        only_gov = True
    else:
        template = 'invite'
        only_gov = False

    # if we've reached here we are POST, and they've asked us to invite
    try:
        email = g.emailer.validate_email(request.form.get('email', ''), valid_domains_only=only_gov)

        if g.uaac.does_origin_user_exist(email, app.config['IDP_PROVIDER_ORIGIN']):
            raise ValueError('You already have a valid account.')

        destination = url_for('first_login', _external=True)
        logging.info('redirect for invite: {0}'.format(destination))

        invite = g.uaac.invite_users(email, destination)
        if len(invite['failed_invites']):
            raise RuntimeError('UAA failed to invite the user.')

        invite = invite['new_invites'][0]
        code = uuid.uuid4().hex
        verification_url = url_for('redeem_invite', verification_code=code, _external=True)

        g.redis.setex(code, app.config['UAA_INVITE_EXPIRATION_IN_SECONDS'], invite['inviteLink'])
        logging.info('Success: Stored link {1} in redis under key {0}'.format(code, invite['inviteLink']))

        branding = {
            'company_name': app.config['BRANDING_COMPANY_NAME']
        }
        subject = render_template('email/subject.txt', invite=invite, branding=branding).strip()
        body = render_template('email/body.html', verification_url=verification_url, branding=branding)

        g.emailer.send_email(email, subject, body)

        return render_template('{0}_sent.html'.format(template))
    except InvalidDomainError as exc:
        flash(str(exc))
        return render_template('{0}.html'.format(template))
    except (EmailNotValidError, ValueError) as exc:
        # email is not valid, exception message is human-readable
        flash(str(exc))
        return render_template('{0}.html'.format(template))
    except UAAError as exc:
        # if UAA complains that our access token is invalid then force them back through the login
        # process.
        # TODO: Fix this properly by implementing the refresh token oauth flow
        # in the UAAClient when it detects it's token is no longer valid
        if 'Invalid access token' in str(exc):
            return redirect(url_for('logout'))
        else:
            logging.exception('An error occured communicating with UAA')
            return render_template('error/internal.html'), 500
    except Exception as exc:
        return render_template('error/internal.html'), 500


@app.route('/redeem-invite', methods=['GET', 'POST'])
def redeem_invite():
    code = request.args.get('verification_code')
    invite = g.redis.get(code)

    if not invite:
        logging.info('The invitation link had a missing or invalid code.')
        return render_template('error/token_validation.html'), 401

    invite_url = bytes.decode(invite)
    logging.info('Accessed UAA invite link. {0}: {1}'.format(code, invite_url))

    if request.method == 'GET':
        redeem_link = url_for('redeem_invite', verification_code=code, _external=True)
        return render_template('redeem-confirm.html', redeem_link=redeem_link)

    g.redis.delete(code)
    return redirect(invite_url, code=302)


@app.route('/first-login', methods=['GET'])
def first_login():
    token = g.uaac.get_user_token()
    user = g.uaac.get_user(token['user_id'])
    logging.info('USER: {0}'.format(user))

    if user['origin'] == 'uaa':
        user['origin'] = app.config['IDP_PROVIDER_ORIGIN']
        user['externalId'] = user['userName']
        g.uaac.put_user(user)

    if user['origin'] == app.config['IDP_PROVIDER_ORIGIN']:
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
    if old_password == new_password or old_password == repeat_password:
        errors.append('Your new password cannot match your old password.')
    if not old_password:
        errors.append('Your old password cannot be blank.')
    if not new_password:
        errors.append('Your new password cannot be blank.')
    if not repeat_password:
        errors.append('You must repeat your new password.')
    if new_password != repeat_password:
        errors.append('Your new password does not match your repeated password.')

    if errors:
        for error in errors:
            flash(error)
        return render_template('change_password.html')

    token = g.uaac.get_user_token()

    try:
        g.uaac.change_password(token['user_id'], old_password, new_password)
        return render_template('password_changed.html')
    except UAAError as exc:
        for error in str(exc).split(','):
            flash(error)
        return render_template('change_password.html')
    except Exception:
        logging.exception('Error changing password')

    return render_template('error/internal.html'), 500


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # start with giving them the form
    if request.method == 'GET':
        return render_template('forgot_password.html')

    # if we've reached here we are POST so we can email user link
    try:
        email = g.emailer.validate_email(request.form.get('email_address', ''))
    except (EmailNotValidError, ValueError) as exc:
        # email is not valid, exception message is human-readable
        flash(str(exc))
        return render_template('forgot_password.html')

    # If we've made it this far, it's a valid email so we'll generate and store a
    # token and send an email.
    logging.info('generating validation token for user')
    identity_token = uuid.uuid4().hex

    branding = {
        'company_name': app.config['BRANDING_COMPANY_NAME']
    }

    reset = {
        'verifyLink': url_for('reset_password', validation=identity_token, _external=True)
    }
    logging.info(reset['verifyLink'])

    subject = render_template('email/subject-password.txt', reset=reset, branding=branding).strip()
    body = render_template('email/body-password.html', reset=reset, branding=branding)

    try:
        g.redis.setex(email, app.config['FORGOT_PW_TOKEN_EXPIRATION_IN_SECONDS'], identity_token)

        g.emailer.send_email(email, subject, body)

        return render_template('forgot_password.html', email_sent=True, email=email)
    except Exception as exc:
        logging.warning("Error sending email: {0}".format(exc))
        return render_template('error/internal.html'), 500


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # start with giving them the form
    if request.method == 'GET':
        code = request.args.get('validation', None)
        if not code:
            flash('The password validation link is incomplete. Please verify your link is correct and try again.')

        return render_template('reset_password.html', validation_code=code)

    # if we've reached here we are POST so we can email user link
    token = request.form.get('_validation_code', '')
    email = request.form.get('email_address', '')

    try:
        email = g.emailer.validate_email(request.form.get('email_address', ''))
    except (EmailNotValidError, ValueError) as exc:
        # email is not valid, exception message is human-readable
        flash(str(exc))
        return render_template('reset_password.html')

    # If we've made it this far, it's a valid email so let's verify the generated
    # token with their email address.

    userToken = g.redis.get(email)

    if userToken.decode('utf-8') == token:
        logging.info('Successfully verified token {0} for {1}'.format(userToken, email))
        g.redis.delete(email)
    else:
        flash('Valid token not found. Please try your forgot password request again.')
        return render_template('reset_password.html')

    temporaryPassword = generate_password()
    try:
        g.uaac.set_password(email, temporaryPassword)
        logging.info('Set temporary password for {0}'.format(email))
        return render_template('reset_password.html', password=temporaryPassword)
    except UAAError as exc:
        flash('Unable to set temporary password. Did you use the right email address?')
        return render_template('reset_password.html')
    except Exception:
        logging.exception('Unable to set your temporary password.')

    return render_template('error/internal.html'), 500


@app.route('/logout')
def logout():
    session.clear()

    return redirect(url_for('index'))


def create_app(env=os.environ):
    # copy these environment variables into app.config
    for ck, default in CONFIG_KEYS.items():
        app.config[ck] = env.get(ck, default)

    # do boolean checks on this variable
    app.config['UAA_VERIFY_TLS'] = str_to_bool(app.config['UAA_VERIFY_TLS'])

    # make sure our base url doesn't have a trailing slash as UAA will flip out
    app.config['UAA_BASE_URL'] = app.config['UAA_BASE_URL'].rstrip('/')

    app.secret_key = app.config['UAA_CLIENT_SECRET']

    # by default connect to localhost for redis
    app.config['REDIS_PARAMS'] = {
        'host': 'localhost',
        'port': 6379,
        'password': ''
    }

    APP_ROOT = os.path.dirname(os.path.abspath(__file__))
    APP_STATIC = os.path.join(APP_ROOT, 'static')

    # default list of domains
    app.config['VALID_DOMAINS'] = ['.mil']

    # add everything from this CSV
    with open(os.path.join(APP_STATIC, app.config['VALID_DOMAIN_LIST'])) as fh:
        for row in csv.reader(fh):
            app.config['VALID_DOMAINS'].append(row[0].lower())

    # if we are running in CF, get redis from the environment
    if 'VCAP_SERVICES' in env:
        services = json.loads(env['VCAP_SERVICES'])
        redis_info = services['redis28'][0]['credentials']

        app.config['REDIS_PARAMS'] = {
            "host": redis_info['hostname'],
            "port": int(redis_info['port']),
            "password": redis_info['password'],
            "socket_timeout": 0.5,
            "socket_connect_timeout": 0.5
        }

    try:
        cf_app_config = json.loads(env['VCAP_APPLICATION'])
        app.config['SERVER_NAME'] = cf_app_config['uris'][0]
        app.config['PREFERRED_URL_SCHEME'] = 'https'
    except (ValueError, KeyError):
        app.config['SERVER_NAME'] = env.get('SERVER_NAME', 'localhost:5000')
        app.config['PREFERRED_URL_SCHEME'] = 'http'

    logging.info('Loaded application configuration:')
    for ck in sorted(CONFIG_KEYS.keys()):
        logging.info('{0}: {1}'.format(ck, app.config[ck]))

    if env.get('ENV') == 'production':   # pragma: no cover
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

    return app
