import logging
import random
import time

from datetime import datetime, timedelta
from flask import render_template, url_for
from multiprocessing import Process
from redis import StrictRedis
from schedule import Scheduler
from uaaextras.clients import UAAClient
from uaaextras.email import Emailer
from uaaextras.webapp import create_app

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class JobScheduler(Process):
    """Run scheduled jobs in their own process with access to the flask application context"""
    def __init__(self):
        super(JobScheduler, self).__init__()

        self.app = create_app()
        self.uaac = UAAClient(
            self.app.config['UAA_BASE_URL'],
            self.app.config['UAA_CLIENT_ID'],
            self.app.config['UAA_CLIENT_SECRET'],
            verify_tls=self.app.config['UAA_VERIFY_TLS']
        )
        self.emailer = Emailer(
            self.app.config['SMTP_FROM'],
            self.app.config['SMTP_HOST'],
            self.app.config['SMTP_PORT'],
            self.app.config['SMTP_USER'],
            self.app.config['SMTP_PASS']
        )
        self.redis = StrictRedis(**self.app.config['REDIS_PARAMS'])

    def render_template(self, *args, **kwargs):
        """Render a flask template inside the app context"""
        with self.app.app_context():
            return render_template(*args, **kwargs)

    def url_for(self, *args, **kwargs):
        """Generate urls from the app context"""
        with self.app.app_context():
            return url_for(*args, **kwargs)

    def get_expiring_users(self):
        """Retrieve a list of expiring users from UAA"""
        list_filter = 'origin eq "{0}"'.format(self.app.config['IDP_PROVIDER_ORIGIN'])

        expiring_users = {}

        now = datetime.now()
        start = 1
        while True:
            users = self.uaac.users(list_filter, start=start)

            for user in users['resources']:
                # parse the timestamp
                passwordLastModified = datetime.strptime(user.get('passwordLastModified'), '%Y-%m-%dT%H:%M:%S.%fZ')
                expiredDelta = timedelta(days=int(self.app.config['PW_EXPIRES_DAYS']))
                lastModifiedDaysDiff = (now - passwordLastModified).days
                daysUntilExpiration = int(self.app.config['PW_EXPIRES_DAYS']) - lastModifiedDaysDiff

                isNotExpired = passwordLastModified > (now - expiredDelta)
                shouldWarn = int(self.app.config['PW_EXPIRATION_WARN_DAYS']) >= daysUntilExpiration

                if shouldWarn and isNotExpired:
                    expiring_users[user.get('userName')] = daysUntilExpiration

            totalResults = int(users['totalResults'])
            itemsPerPage = int(users['itemsPerPage'])

            numPages, remainder = divmod(totalResults, itemsPerPage)
            if remainder:
                numPages += 1

            currentPage, remainder = divmod(start, itemsPerPage)

            if currentPage + 1 < numPages:
                start = start + itemsPerPage
            else:
                break

        return expiring_users

    def expiring_password_notification(self):
        """Send email notification to users whos passwords are expiring soon"""
        try:
            self.redis.ping()
        except Exception as exc:
            logging.warning("Unable to connect to redis: {0}".format(exc))
            return

        now = datetime.now().date()
        ranToday = self.redis.get(now)

        if ranToday:
            logging.info("Already run today, skipping! ({0} {1})".format(now, ranToday))
            return

        logging.info("Starting run at {0}: {1}".format(now, ranToday))
        # Let's make sure we don't run again today, and we can expire in a week
        self.redis.setex(now, timedelta(days=7), True)

        branding = {
            'company_name': self.app.config['BRANDING_COMPANY_NAME']
        }

        for email, daysUntilExpiration in self.get_expiring_users().items():
            logging.info('{0} expires in {1} days'.format(email, daysUntilExpiration))
            password = {
                'daysUntilExpiration': daysUntilExpiration,
                'changeLink': self.url_for('change_password', _external=True)
            }

            subject = self.render_template('email/subject-expiring-password.txt',
                                           password=password, branding=branding).strip()
            body = self.render_template('email/body-expiring-password.html',
                                        password=password, branding=branding)
            self.emailer.send_email(email, subject, body)

    # no cover on this because unit tests flip when trying to test subprocesses
    # and this function gets executed by multiprocessing in it's own process
    def run(self):  # pragma: no cover
        """Ensure the jobs provided by this class are run at specified intervals"""
        logging.info("Starting job scheduler!")

        scheduler = Scheduler()

        # between 8 and 8:30
        job_time = "08:{0}".format(str(random.randint(0, 30)).zfill(2))
        scheduler.every().day.at(job_time).do(self.expiring_password_notification)

        try:
            while True:
                scheduler.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            pass
