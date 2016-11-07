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
        'gunicorn==19.6.0',
        'flask==0.11.1',
        'requests==2.11.1',
        'email_validator==1.0.1',
        'talisman==0.1.0'
    ],

    test_suite='uaainvite.tests',

    tests_require=[
        'blinker',
        'httmock',
        'mock'
    ]
)
