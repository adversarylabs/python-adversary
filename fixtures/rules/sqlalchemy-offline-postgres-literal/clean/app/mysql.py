from sqlalchemy import String


def escape_mysql(database, value: str) -> str:
    dialect = database.get_dialect()
    if dialect.name not in ("mysql", "mariadb"):
        return value
    compiler = dialect.statement_compiler(dialect, None)
    return compiler.render_literal_value(value, String())[1:-1]
