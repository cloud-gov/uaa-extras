#!/usr/bin/env python3
"""Run the webapp in debug mode"""

from uaaextras.webapp import create_app

if __name__ == "__main__":
    # this runs in it's own process
    app = create_app()

    app.run(debug=True)
