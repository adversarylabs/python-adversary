from sqlalchemy import String
from sqlalchemy.dialects import postgresql


def escape_with_direct_dialect(value: str) -> str:
    dialect = postgresql.dialect()
    compiler = dialect.statement_compiler(dialect, None)
    return compiler.render_literal_value(value, String())[1:-1]
