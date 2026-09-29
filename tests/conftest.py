import os
import tempfile

import pytest

KEY = b"brandpulse-test-key-0123456789"


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "audit.db")
