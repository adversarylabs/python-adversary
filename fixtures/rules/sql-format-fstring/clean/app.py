def q(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
