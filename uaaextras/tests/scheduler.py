from datetime import datetime, timedelta
import unittest

from flask import url_for, render_template
from mock import Mock, patch

from uaaextras.scheduler import JobScheduler
from uaaextras.webapp import create_app


class TestJobScheduler(unittest.TestCase):

    def setUp(self):
        self.redis = Mock()
        self.redis_patch = patch('uaaextras.scheduler.StrictRedis', Mock(return_value=self.redis))
        self.redis_patch.start()

        self.uaac = Mock()
        self.uaac_patch = patch('uaaextras.scheduler.UAAClient', Mock(return_value=self.uaac))
        self.uaac_patch.start()

        self.emailer = Mock()
        self.emailer_patch = patch('uaaextras.scheduler.Emailer', Mock(return_value=self.emailer))
        self.emailer_patch.start()

        self.job = JobScheduler()
        self.job.app.config['PW_EXPIRES_DAYS'] = 90
        self.job.app.config['PW_EXPIRATION_WARN_DAYS'] = 5

        self.passgood = (datetime.now() - timedelta(days=26)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        self.passwarn = (datetime.now() - timedelta(days=85)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        self.passexpire = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        self.passreallyexpire = (datetime.now() - timedelta(days=200)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def tearDown(self):
        self.redis_patch.stop()
        self.uaac_patch.stop()
        self.emailer_patch.stop()

    def test_notify_expiring_no_redis_connection(self):
        """When there is no redis connection, don't even connect to UAA"""

        self.redis.ping.side_effect = Exception()

        self.job.expiring_password_notification()

        self.redis.get.assert_not_called()
        self.uaac.users.assert_not_called()

    def test_get_expiring_no_results(self):
        """When UAA returns no results, make sure we don't do any time paging"""

        self.uaac.users.return_value = {'totalResults': 0, 'itemsPerPage': 100, 'resources': []}

        results = self.job.get_expiring_users()

        self.assertEqual(len(results), 0)
        self.uaac.users.assert_called_once()

    def test_get_expiring_not_enough_to_page(self):
        """When When UAA does return results, do not page because not enough results"""

        self.uaac.users.return_value = {
            'totalResults': 1,
            'itemsPerPage': 1,
            'resources': [
                {
                    'userName': 'test@example.org',
                    'passwordLastModified': self.passgood
                }
            ]
        }

        results = self.job.get_expiring_users()
        self.assertEqual(len(results), 0)
        self.uaac.users.assert_called_once()

    def test_get_expiring_paging(self):
        """When When UAA does return results, do email, and paging"""

        # This should give us 3 pages of results
        self.uaac.users.side_effect = [
            {
                'totalResults': 5,
                'itemsPerPage': 2,
                'resources': [
                    {
                        'userName': 'test1@example.org',
                        'passwordLastModified': self.passgood
                    },
                    {
                        'userName': 'test2@example.org',
                        'passwordLastModified': self.passgood
                    }
                ]
            },
            {
                'totalResults': 5,
                'itemsPerPage': 2,
                'resources': [
                    {
                        'userName': 'test3@example.org',
                        'passwordLastModified': self.passgood
                    },
                    {
                        'userName': 'test4@example.org',
                        'passwordLastModified': self.passgood
                    }
                ]
            },
            {
                'totalResults': 5,
                'itemsPerPage': 2,
                'resources': [
                    {
                        'userName': 'test5@example.org',
                        'passwordLastModified': self.passgood
                    }
                ]
            }
        ]

        results = self.job.get_expiring_users()
        self.assertEqual(len(results), 0)
        self.assertEqual(self.uaac.users.call_count, 3)

    def test_get_expiring_warn(self):
        """When user password expires within warning days, return user"""

        self.uaac.users.return_value = {
            'totalResults': 4,
            'itemsPerPage': 4,
            'resources': [
                {
                    'userName': 'test1@example.org',
                    'passwordLastModified': self.passgood
                },
                {
                    'userName': 'test99@example.org',
                    'passwordLastModified': self.passreallyexpire
                },
                {
                    'userName': 'test2@example.org',
                    'passwordLastModified': self.passwarn
                },
                {
                    'userName': 'tes3@example.org',
                    'passwordLastModified': self.passexpire
                }
            ]
        }

        results = self.job.get_expiring_users()
        self.uaac.users.assert_called_once()

        # only one user should be passed to us
        self.assertEqual(len(results), 1)
        self.assertIn('test2@example.org', results)
        self.assertEqual(results['test2@example.org'], 5)

    def test_expiring_job_uses_redis_lock(self):
        """If there's a key in redis, don't run"""

        self.redis.get.return_value = True

        self.job.expiring_password_notification()
        self.redis.setex.assert_not_called()

    @patch('uaaextras.scheduler.JobScheduler.get_expiring_users')
    def test_email_notifications(self, get_users):
        """When there are expiring users, emails are sent"""

        get_users.return_value = {
            "foo@example.com": 4,
            "bar@example.com": 1
        }

        self.redis.get.return_value = False

        self.job.expiring_password_notification()
        self.redis.setex.assert_called_once()

        self.assertEqual(self.emailer.send_email.call_count, 2)

    def test_app_context(self):
        """Class methods should return same values as app native calls"""

        app = create_app()
        with app.test_request_context('/'):
            self.assertEqual(
                self.job.url_for('change_password', _external=True),
                url_for('change_password', _external=True)
            )
            self.assertEqual(
                self.job.render_template('error/internal.html'),
                render_template('error/internal.html')
            )
