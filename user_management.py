import sqlite3 as sql
import time
import random
import bcrypt


def insertUser(username, hashed_password_bytes, DoB):

    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password_bytes, DoB),
    )
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
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()
