from setuptools import setup, find_packages

setup(
    name='uaainvite',

    version='0.0.1',

    description='A simple UI for the UAA /invite_users endpoint',

    url='https://github.com/18F/cg-uaa-invite',

    author='Chris Nelson',
    author_email='cnelson@cnelson.org',

    license='Public Domain',

    packages=find_packages(),

    install_requires=[
        'gunicorn',
        'flask',
        'requests',
        'email_validator',
        'pyjwt'
    ],

    test_suite='uaainvite.tests',

    tests_require=[
        'blinker',
        'httmock',
        'mock'
    ]
)
