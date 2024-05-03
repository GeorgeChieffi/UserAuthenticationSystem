import ssl
import socket

# Path to Servers Certificate
SERVERCERTPATH = "../Server/rootCA.pem"

# Adddress and port of the Server
HOST = 'localhost'
PORT = 50000

# Max lengths for each part of the header
COMMAND_SIZE = 2
HEADER_SIZE = 10

# Default menu
menu = "Please select an option below:\n1 - login\n2 - signup\n"


# Checks if the users password is compliant with the rules
def checkPassword(str) -> bool:
    length = 0
    upperCase = 0
    specialChars = 0
    numbers = 0

    for i in str:
        if i.isupper():
            upperCase += 1
        if not i.isalnum():
            specialChars += 1
        if i.isnumeric():
            numbers += 1
        length += 1


    if length >=12 and upperCase >= 2 and specialChars >= 2 and numbers >= 2:
        return True
    return False

# Handles gathering users input for signup message
def sendSignup():
    username = input("Username: ")
    while True:
        print("\nFollow these rules to create a strong password:\n1- Must have a minimum length of 12 characters\n2- At least 2 Upper Case letters\n3- At least 2 special characters\n4- At least 2 numbers\n")
        password1 = input("Password: ")
        password2 = input("Re-Enter Password: ")
        if password1 == password2 and checkPassword(password1):
            break
        elif password1 != password2:
            print("\nPasswords dont match. Try again\n")
        else:
            print("Please follow the password rules!")

    # Create the data for the message
    data = username + '&' + password1

    # Formats the command header to be of len 2
    commandHeader = f'{int(2):<{COMMAND_SIZE}}'

    # Formats the command header to be of len 10
    lengthHeader = f'{len(data):<{HEADER_SIZE}}'

    # Encode the message in UTF-8
    message = bytes(commandHeader + lengthHeader + data ,'utf-8')

    # Send message to the server
    return(message)

# Handles gathering users input for the login message
def sendLogin():
    username = input("Username: ")
    password = input("Password: ") # could use pwinput to hide users input and mask as *

    # builds data part of message
    data = username + "&" + password
    
    # Formats the command header to be of len 2
    commandHeader = f'{int(1):<{COMMAND_SIZE}}'

    # Formats the command header to be of len 10
    lengthHeader = f'{len(data):<{HEADER_SIZE}}'

    # Encodes the entire message in UTF-8
    message = bytes(commandHeader + lengthHeader + data ,'utf-8')

    # Sends message to the server
    return(message)

# Handles gathering the flag from the user
def handleFlag():
    data = input("Enter the flag: ")
    commandHeader = f'{int(9):<{COMMAND_SIZE}}'
    lengthHeader = f'{len(data):<{HEADER_SIZE}}'
    message = bytes(commandHeader + lengthHeader + data, 'utf-8')

    return message


def main():
    # Create an SSL context with the servers certificate
    context = ssl.create_default_context()
    context.load_verify_locations(SERVERCERTPATH)
    context.check_hostname = False

    # Creates a socket connection
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Wrap connection with SSL context
    # This encrypts the information sent between the server and client
    # Prevents MITM attacks
    conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)

    # Uses the SSL wrapped socket connection to connect to the server
    try:
        conn.connect((HOST, PORT))
        # Wait for server response
        while True:
            # Read from Server
            data_len = conn.recv(HEADER_SIZE)
            data = conn.recv(int(data_len.decode())).decode()
            if int(data_len.decode()) > 50 and 'CTF' in data:
                global menu
                menu = "9 - Secret Flag\n"
            print(data)
            if 'Server - CLOSED' in data:
                conn.close()
                break

            option = 0
            # allows user to choose an option from the menu
            while option not in range(1,3) and option != 9:
                option = int(input(menu))
            if option == 1:
                # Send login request with users input
                conn.send(sendLogin())
            elif option == 2:
                # Send signup request with users input
                conn.send(sendSignup())
            elif option == 9:
                # Send secret request with users secret
                conn.send(handleFlag())
    except Exception as error:
        print(f"There was an error connecting to the server.\nERROR: {error}")

# run client
main()