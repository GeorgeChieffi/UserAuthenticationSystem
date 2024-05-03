import sqlite3
from argon2 import PasswordHasher

ph = PasswordHasher()
BUFF_SIZE = 1024

def signup(username, rawpassword):
    try:
        dbConn = makeDBConn()
        dbCursor = dbConn.cursor()
        # hashedPW = ph.hash(rawpassword) # just inserted directly into insert statment so no memory holds the hashed pw
        dbCursor.execute(f"INSERT INTO users (username, password) VALUES (?, ?);", (username, ph.hash(rawpassword),))
        dbConn.commit()

        res = '\nServer - Succsussfull Registration!\n'
    except Exception as error:
        res = f'\nServer - There was an error signing up. Try again later\nServer - ERROR: {error}\n'

    return res


def login(username, rawpassword): 
    dbConn = makeDBConn()
    dbCursor = dbConn.cursor()
    dbCursor.execute("SELECT password FROM users WHERE username=?",(username,))
    userPass = dbCursor.fetchone()

    if userPass == None:
        return f"\nServer - The specified user is not in the database: {username}\n"
    try:
        ph.verify(userPass[0],rawpassword) # get userspass from db compared to entered pass
        res = '\nServer - You are now logged in!\nServer - Take the secret flag: CTF{C0ngr@tZ_on_$ecur3ly_4uthent1c@t1ng_Y0urs3lf}\n'

    except Exception as error:
        res = f'\nServer - There was an error logging you in. Please try again later.\nServer - ERROR: {error}\n'
    
    return res

def makeDBConn() -> sqlite3.Connection:
    db_path = "./SecureAuth.db"
    connection = sqlite3.connect(db_path)
    return connection
