# Database Layer with Seeded SAST Flaws

def get_user_by_username(cursor, username: str):
    # CWE-89: SQL Injection via direct f-string interpolation into SQL query
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def delete_user_records(cursor, user_id: int):
    # Safe parameterized query
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
