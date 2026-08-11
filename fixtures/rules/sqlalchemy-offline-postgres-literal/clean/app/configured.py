from sqlalchemy import String


def escape_postgresql(database, value: str) -> str:
    dialect = database.get_dialect()
    if dialect.name != "postgresql":
        return value
    compiler = dialect.statement_compiler(dialect, None)
    compiler._backslash_escapes = False
    return compiler.render_literal_value(value, String())[1:-1]
