from setuptools import setup, find_packages

setup(
    name='uaaextras',

    version='0.0.1',

    description='A simple UI for UAA /invite_users endpoint and password resets',

    url='https://github.com/18F/cg-uaa-extras',

    author='Chris Nelson',
    author_email='cnelson@cnelson.org',

    license='Public Domain',

    packages=find_packages(exclude=['integration_tests*', 'test']),

    install_requires=[
        'gunicorn==19.10.0',
        'flask==1.1',
        'requests==2.23.0',
        'email_validator==1.0.1',
        'talisman==0.1.0',
        'redis==2.10.5',
        'zxcvbn-python==4.4.24',
        'sqlalchemy==1.3.15',
        'psycopg2==2.8.5',
    ],

    test_suite='uaaextras.tests',

    tests_require=[
        'blinker',
        'httmock',
        'mock'
    ]
)
