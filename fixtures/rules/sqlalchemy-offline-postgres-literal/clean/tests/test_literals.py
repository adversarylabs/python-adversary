from sqlalchemy import String


def test_postgresql_literal(database, value: str) -> str:
    dialect = database.get_dialect()
    if dialect.name != "postgresql":
        return value
    compiler = dialect.statement_compiler(dialect, None)
    return compiler.render_literal_value(value, String())[1:-1]
