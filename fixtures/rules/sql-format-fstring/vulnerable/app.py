def q(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
