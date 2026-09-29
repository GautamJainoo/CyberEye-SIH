"""Test isolation: never touch the real assessment database (backend/wmsa.db)."""

import os
import tempfile

# Must be set before any test module imports wmsa.api (which builds a global Database at import time).
os.environ["WMSA_DB_PATH"] = os.path.join(tempfile.mkdtemp(prefix="wmsa-tests-"), "wmsa_test.db")


import socket

import pytest


@pytest.fixture
def closed_port():
    """A loopback port nothing is listening on, so 'target offline' tests hold even if a real target runs."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
