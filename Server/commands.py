import sqlite3
from argon2 import PasswordHasher

# Create an Argon2 PasswordHashing object
ph = PasswordHasher()


# Handles DB interactions with the supplied username and password for signup
def signup(username, rawpassword):
    try:
        dbConn = makeDBConn()
        dbCursor = dbConn.cursor()

        # Creates a new user in the users table with the supplied username and hashed password
        dbCursor.execute(f"INSERT INTO users (username, password) VALUES (?, ?);", (username, ph.hash(rawpassword),))
        dbConn.commit()

        res = '\nServer - Succsussfull Registration!\n'
    except Exception as error:
        # Sends the client an error if they couldnt register and account
        res = f'\nServer - There was an error signing up. Try again later\nServer - ERROR: {error}\n'

    return res

# Handles DB interactions with the supplied username and password for login
def login(username, rawpassword): 
    dbConn = makeDBConn()
    dbCursor = dbConn.cursor()
    
    # executes a select query and storing the first record where the usernames match
    dbCursor.execute("SELECT password FROM users WHERE username=?",(username,))
    userPass = dbCursor.fetchone()

    if userPass == None:
        return f"\nServer - The specified user is not in the database: {username}\n"
    try:
        # verifies the supplied password matches the stored hashed password
        # ph.verify will return an error if they dont match so it must be wrapped in a try except
        ph.verify(userPass[0],rawpassword) # get userspass from db compared to entered pass
        res = '\nServer - You are now logged in!\nServer - Take the secret flag: CTF{C0ngr@tZ_on_$ecur3ly_4uthent1c@t1ng_Y0urs3lf}\n'

    except Exception as error:
        res = f'\nServer - There was an error logging you in. Please try again later.\nServer - ERROR: {error}\n'
    
    return res

# Create a connection to the DataBase
def makeDBConn() -> sqlite3.Connection:
    db_path = "./SecureAuth.db"
    connection = sqlite3.connect(db_path)
    return connection
