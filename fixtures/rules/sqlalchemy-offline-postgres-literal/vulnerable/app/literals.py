from sqlalchemy import String


def escape_for_database(database, value: str) -> str:
    dialect = database.get_dialect()
    compiler = dialect.statement_compiler(dialect, None)
    return compiler.render_literal_value(value, String())[1:-1]
