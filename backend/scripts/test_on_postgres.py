#!/usr/bin/env python
"""Run the test suite against a throw-away real PostgreSQL (no Docker needed). Needs requirements-dev.txt."""
import os
import subprocess
import sys
import tempfile
import urllib.parse as up
from pathlib import Path

import pgserver

BACKEND = Path(__file__).resolve().parent.parent
os.chdir(BACKEND)
server = pgserver.get_server(tempfile.mkdtemp(prefix="pgdata_"), cleanup_mode="stop")
host = up.parse_qs(up.urlparse(server.get_uri()).query)["host"][0]
settings_file = BACKEND / "config" / "settings_pg_test.py"
settings_file.write_text(
    "from .settings_test import *\n"
    f'DATABASES = {{"default": {{"ENGINE": "django.db.backends.postgresql", "NAME": "postgres", "USER": "postgres", "PASSWORD": "", "HOST": "{host}", "PORT": ""}}}}\n'
)
try:
    sys.exit(subprocess.run([sys.executable, "manage.py", "test", "--settings=config.settings_pg_test", *sys.argv[1:]]).returncode)
finally:
    settings_file.unlink(missing_ok=True)
