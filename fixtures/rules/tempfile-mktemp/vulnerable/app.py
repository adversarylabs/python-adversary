import tempfile


def log_path() -> str:
    path = tempfile.mktemp(suffix=".log")
    return path
