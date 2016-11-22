#!/usr/bin/env python3
"""Run the webapp in debug mode"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".tox/flake8/lib/python3.5/site-packages"))

from uaaextras.webapp import create_app

if __name__ == "__main__":
    app = create_app()

    app.run(debug=True)
