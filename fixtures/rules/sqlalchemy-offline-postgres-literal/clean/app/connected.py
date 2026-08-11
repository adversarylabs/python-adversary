from sqlalchemy import String


def render_from_connected_engine(engine, value: str) -> str:
    if engine.dialect.name != "postgresql":
        return value
    compiler = engine.dialect.statement_compiler(engine.dialect, None)
    return compiler.render_literal_value(value, String())[1:-1]
