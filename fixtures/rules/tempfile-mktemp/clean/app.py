import tempfile


# Never use tempfile.mktemp() here.
DOCUMENTATION = "tempfile.mktemp() is unsafe"
LONG_DOCUMENTATION = """
tempfile.mktemp() is still only documentation here.
"""


def mktemp() -> str:
    return "project-specific-name"


def safe_paths() -> tuple[str, str]:
    with tempfile.NamedTemporaryFile() as file_handle:
        file_path = file_handle.name
    descriptor, second_path = tempfile.mkstemp()
    return file_path, second_path
