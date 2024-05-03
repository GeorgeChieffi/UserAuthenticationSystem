import ssl
import socket
from socket import SHUT_RDWR
import threading
from commands import login, signup
import sqlite3
import os

HOST = 'localhost'
PORT = 50000
COMMAND_SIZE = 2
HEADER_SIZE = 10
KEYPATH = './rootCA.key'
CERTPATH = './rootCA.pem'
DBPATH = "./SecureAuth.db"

# User object | used to verifiy the clients logged in status
class User():
    def __init__(self, addr):
        self.addr = addr
        self.loggedInStatus = False
    def authenticate(self):
        self.loggedInStatus = True


# create or connect to a database in local dir called 'SecureAuth.db' and create a users table if not already there
def createDB():
    curs = sqlite3.connect(DBPATH).cursor()
    createUserTableQuery = '''
    CREATE TABLE IF NOT EXISTS users (
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    '''
    curs.execute(createUserTableQuery)


def handleClient(conn, addr):
    # Create new visitor object for each client
    visitor = User(addr)
    welcomeMessage = "Welcome to the Server.\nThis connection is now secure!\n"
    conn.send(bytes(f'{len(welcomeMessage):<{HEADER_SIZE}}' + welcomeMessage ,'utf-8'))


    wrongCommandMessage = "ERROR - Your selected command does not match a command on the server please try again"

    # read client Messages
    while True:
        response = wrongCommandMessage
        clientCommand = int(conn.recv(COMMAND_SIZE))

        # Handle a login request from the client
        if clientCommand == 1:
            msglen = int(conn.recv(HEADER_SIZE))
            data = conn.recv(msglen).decode()
            params = data.split('&')

            # pass information to login() to handle database verification
            response = login(params[0], params[1],)
            if 'CTF' in response:
                visitor.authenticate()
                print(f'[{visitor.addr}] - User Authenticated')
            
        # Handle a signup request from the client
        elif clientCommand == 2:
            msglen = int(conn.recv(HEADER_SIZE))
            data = conn.recv(msglen).decode()
            params = data.split('&')

            # pass information to signup() to handle database interaction
            response = signup(params[0], params[1])
            print(f'[{visitor.addr}] - New Registration')


        # Handle special request
        elif clientCommand == 9 and visitor.loggedInStatus:
            msglen = int(conn.recv(HEADER_SIZE))
            data = conn.recv(msglen).decode()
            if data == 'CTF{C0ngr@tZ_on_$ecur3ly_4uthent1c@t1ng_Y0urs3lf}':
                goodbyeMessage = "\nServer - We are now closing your connection. You have succsessfully:\n\tCreated an account\n\tLogged into your accound\n\tPerformed an action on the server reserved for logged in users\nServer - Thank you!\nServer - CLOSED\n"
                conn.send(bytes(f'{len(goodbyeMessage):<{HEADER_SIZE}}' + goodbyeMessage, 'utf-8'))
                
                # close client connection on server
                conn.shutdown(SHUT_RDWR)
                conn.close()
                print(f'[{visitor.addr}] - Connection Closed')
                break
            else:
                response = 'Incorrect Flag'


        # send client a response
        conn.send(bytes(f'{len(response):<{HEADER_SIZE}}' + response ,'utf-8'))
    

def startServer():
    # Create DB if it doesnt exist
    if not os.path.exists(DBPATH):
        createDB()

    # initialize servers SSL(secure socket layer) context with certfile and key
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTPATH, keyfile=KEYPATH)

    # open port on server for clients to connect | max 5 clients at a time
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("localhost", 50000))
    s.listen(5)

    try:
        # client accept loop
        while True:
            conn, addr = s.accept()
            print(f"[{addr}] - Connection Established")

            # Wrap connection with SSL context to encrypt communications
            Secure_Client_Socket = context.wrap_socket(conn, server_side=True)
            print(f'[{addr}] - Connection is now secured with SSL')

            # Create new thread for the client | start thread
            client_thread = threading.Thread(target=handleClient, args=(Secure_Client_Socket,addr,))
            client_thread.start()

    except Exception as error:
        print(error)


# Start the server
startServer()