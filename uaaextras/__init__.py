import os
from uaaextras.scheduler import JobScheduler
from uaaextras.webapp import create_app

if os.environ.get('SCHEDULER'):  # pragma: no cover
    scheduler = JobScheduler()
    scheduler.start()

app = create_app()
