import sqlite3 as sql


def insertUser(username, hashed_password_bytes, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)", (username, hashed_password_bytes, DoB))
    con.commit()
    con.close()


def retrieveUsers(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT rowid, username, password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "password": row[2]
        }
    return None


def retrieveUserbyId(user_id):
    con = sql.connect("database_files/database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    # treat numeric identifier as id, otherwise username
    try:
        cur.execute("SELECT id, username, password FROM users WHERE id = ?", (int(user_id),))
    except ValueError:
        cur.execute("SELECT id, username, password FROM users WHERE username = ?", (user_id,))
    row = cur.fetchone()
    cur.close()
    con.close()
    if not row:
        return None
    row = dict(row)
    return row


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"INSERT INTO feedback (feedback) VALUES ('{feedback}')")
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    return data
