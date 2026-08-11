def find_path(cursor, value: str) -> None:
    cursor.execute("SELECT id FROM files WHERE path = %s", (value,))
