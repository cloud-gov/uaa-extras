from setuptools import setup, find_packages

setup(
    name='uaaextras',

    version='0.0.1',

    description='A simple UI for UAA /invite_users endpoint and password resets',

    url='https://github.com/18F/cg-uaa-extras',

    author='Chris Nelson',
    author_email='cnelson@cnelson.org',

    license='Public Domain',

    packages=find_packages(),

    install_requires=[
        'gunicorn==19.6.0',
        'flask==0.12',
        'requests==2.12.4',
        'email_validator==1.0.1',
        'talisman==0.1.0',
        'redis==2.10.5',
        'schedule==0.4.2'
    ],

    test_suite='uaaextras.tests',

    tests_require=[
        'blinker',
        'httmock',
        'mock'
    ]
)
