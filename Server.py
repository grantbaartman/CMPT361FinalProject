# ------------------------------------------------------------------------------
# Integrity Pledge:
# I declare that the work is being submitted is my own
# It was completed in accordance with MacEwan's Academic Integrity Policy
# Author(s): Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# ------------------------------------------------------------------------------
# Name of Group Members: Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# Program: Server.py
# ------------------------------------------------------------------------------
# Purpose: The program simulates Develop a secure mail transfer protocol 
#          implemented through server and client programs in a UNIX-like 
#          environment. This program can handle multiple clients concurrently 
#          using the fork function to create multiple processes. The program
#          also implemented security measures to reasonably secure the mail 
#          transfer application. Also, Server.py identifies potential attacks 
#          against the developed protocol and enhance it to defend against these
#          attacks.
# ------------------------------------------------------------------------------
# importing crucial libraries to simulate a secure mail transfer protocol
import hashlib
import json
import os
import socket
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from datetime import datetime as d


def generateSymmetricKey():
    '''
    Purpose: Generate a symmetric key for encryption using AES with a key length of 256 bits.
    Parameter: None
    Return: symKey - The generated symmetric key
    '''
    # Generate a random symmetric key using AES with a key length of 256 bits
    symKey = get_random_bytes(32)  # 256 bits key length
    return symKey
# end generateSymmetricKey()


def encryptMessage(message, publicKey):
    '''
    Purpose: a helper function that uses assymetrical encryption to secure the
             message
    Parameter: message - a string that holds the text data
               publicKey - a string that holds the public key to the server
    Return: serverPublicKey - the public key of the server
    '''
    # saves the public key to a variable, encrypt the encrypted message, and
    # returns it
    cipher = PKCS1_OAEP.new(publicKey)
    return cipher.encrypt(message)
# end encryptMessage()


def decipherMessage(encryptedMSG, privateKey):
    '''
    Purpose: a helper function that uses assymetrical decryption to decipher the
             message
    Parameter: encryptedMSG - a string that holds the encrypted text data
               privateKey - a string that holds the private key to the server
    Return: serverPublicKey - the public key of the server
    '''
    cipher = PKCS1_OAEP.new(privateKey)
    return cipher.decrypt(encryptedMSG)
# end decipherMessage()


def loadUserInfo():
    '''
    Purpose: a helper function that reads the .json file that holds all known
             users and their passwords
    Parameter: none
    Return: userInfo - a string list of users and their passwords
    '''
    try:
        with open("user_pass.json", "r") as f:
            userInfo = json.load(f)
        # end with
    except FileNotFoundError:
        print(f">> Key files for user information has not been found!")
        print(f">> Initializing known clients...")
        # calls a helper function to initalize a list of clients
        userInfo = startKnownClients()
        # calls a helper function to save it to the .json file
        saveUserInfo(userInfo)
    # end try & accept
        
    return userInfo
# end loadUserInfo()
 

def saveUserInfo(knownClients):
    '''
    Purpose: a helper function that saves the known Clients back to .json file
    Parameter: knownClients - a data structure that holds all known authorized
                              clients
    Return: none
    '''
    try:
        # Save user info to JSON file
        with open("user_pass.json", "w") as file:
            json.dump(knownClients, file, indent = 4)
        print(">> User info saved to 'user_pass.json'")
    except Exception as e:
        print(">> Error:", e)
    # end try & accept
# end saveUserInfo()
        

def startKnownClients():
    '''
    Purpose: a helper function that initializes a dictionary with known
             authorized users for clients
    Parameter: none
    Return: knownClients - the dictionary with known clients
    '''
    # initiallizes a dictionary with all 5 authorized clients
    knownClients = {
        "John": "badboat68",
        "David": "(oolheat19",
        "Lucy": "b!gBox99",
        "Dorio": "calmKoala41",
        "Bob": "123456"
    }

    return knownClients
# end startknownCLients()


def authenticateUser(username, password):
    '''
    Purpose: a helper function that checks if the user is in the file for
             authorized users along with their password
    Parameter: username - a string that holds the username
               password - a string that holds the password
    Return: a boolean that indicates if the user is authorized or not
    '''
    # calls helper function to get information
    userPass = loadUserInfo()
    # checks and returns a boolean value
    return username in userPass and userPass[username] == password
# end authenticateUser()


def loadClientPublicKey(clientPublicKeyFile):
    '''
    Purpose: Load a private key from a file
    Parameter: clientPublicKeyFile - the file path of the private key
    Return: clientPublicKeyFile - the loaded private key object
    '''
    try:
        with open(clientPublicKeyFile, "r") as file:
            publicKey = RSA.import_key(file.read())
        return publicKey
    except Exception as e:
        print(f">> Error loading public key from file {clientPublicKeyFile}: {e}")
        return None
    # end try & accept
# end loadClientPublicKey()


def loadServerPublicKey():
    '''
    Purpose: a helper function that loads the public key of the server
    Parameter: username - a string that holds the username given
    Return: serverPublicKey - the public key of the server
    '''
    try:
        with open("server_public.pem", 'r') as file:
            serverPublicKey = RSA.import_key(file.read())

            # # checks if the file is not empty
            # if keyData:
            #     try:
            #         serverPublicKey = RSA.import_key(keyData)
            #     except ValueError:
            #         # when file contains invalid key data, generate a new key
            #         print(">> Invalid server public key data. Generating new server's public key...")
            #         serverPublicKey = RSA.generate(2048)
            #         # save the new generated key
            #         saveServerPublicKey(serverPublicKey)
            # else:
            #     # if the file is empty, generate a new key
            #     print(">> Empty server public key file. Generating new server's public key...")
            #     serverPublicKey = RSA.generate(2048)
            #     # save the new generated key
            #     saveServerPublicKey(serverPublicKey)
            # # end if statement
    except FileNotFoundError:
        print(">> Server public key file not found. Generating server's public key...")
        # calls the RSA generation to generate a key
        serverPublicKey = RSA.generate(2048)
        # calls a helper function to save the generatedServerPublicKey
        saveServerPublicKey(serverPublicKey)
    except ValueError as e:
        print(f">> Error loading server public key: {e}")
        print(">> Generating new server's public key...")

        # generate a new key if the loaded key is invalid
        serverPublicKey = RSA.generate(2048)

        # save the generated key
        saveServerPublicKey(serverPublicKey)
        print(">> New server public key generated and saved.")
    # end try & accept
        
    return serverPublicKey
# end loadServerPublicKey()


def saveServerPublicKey(publicKey):
    '''
    Purpose: a helper function that saves the generated server public key
    Parameter: publicKey - a string that is the server key
    Return: none
    '''
    try:
        with open("server_public.pem", 'wb') as file:
            file.write(publicKey.export_key() )
        print(">> Server's public key saved as 'server_public.pem'")
    except Exception as e:
        print(">> Error:", e)
    # end try & accept
# end saveServerPublicKey()
        

def startCreatingUserKeys():
    '''
    Purpose: a helper function that creates a public and private key for all 5
             known users. This function is similar to startKnownClients()
    Parameter: none
    Return: none
    '''
    # define the names of the known users
    knownUsers = ["John", "David", "Lucy", "Dorio", "Bob"]

    # loops until the known users are done
    for username in knownUsers:
        # generate a key pair for the user
        keyPair = RSA.generate(2048)
        publicKey = keyPair.publickey().export_key()
        privateKey = keyPair.export_key()

        # save the public key to a .pem file
        publicKeyFilename = f"{username}_public.pem"
        with open(publicKeyFilename, 'wb') as f:
            f.write(publicKey)
        # end with
            
        # save the private key to a .pem file
        privateKeyFilename = f"{username}_private.pem"
        with open(privateKeyFilename, 'wb') as f:
            f.write(privateKey)
        # end with
            
        print(f"\t>>Key pair generated for user '{username}'")
    # end for loop
        
    print(">> Public and private keys saved as .pem files.")
# end startCreatingUserKeys()


def checkPemFilesExist():
    '''
    Purpose: Check if .pem files exist for each user
    Parameter: None
    Return: True if .pem files exist for all users, False otherwise
    '''
    # define the names of the known users
    knownUsers = ["John", "David", "Lucy", "Dorio", "Bob"]

    # loops and checks if .pem files exist for each user
    for username in knownUsers:
        public_key_filename = f"{username}_public.pem"
        private_key_filename = f"{username}_private.pem"

        # check if both public and private key files exist for the user
        if not (os.path.exists(public_key_filename) and os.path.exists(private_key_filename)):
            return False
        # end if statement
    # end for loop
    return True
# end checkpemFilesExist()


def createEmail(clientSocket,serverPubKey,clientpubkey):

    '''
    Purpose: a helper function that lets the user create and send an email to
             the server
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
    encrypted_message=encryptMessage("send the email",serverPubKey)
    clientSocket.send(encrypted_message)
    
    encrypted_email=clientSocket.recv(4096)
    decrypted_email=decipherMessage(encrypted_email,clientpubkey)
    
    processEmail(decrypted_email)
   
    clientSocket.sendall(b"Email received by the server.")
# end createEmail()
    

def processEmail(email_object):
    '''
    Parameter: The email json object that's sent from the client side
    purpose: Extract email info, print it to server side, and save the emails to text file 
    return :none
    '''
    destin=''
    #extract email info
    sender=email_object["sender"]
    destination=email_object["destinations"]
    title=email_object["title"]
    length=email_object["content_length"]
    contents=email_object["message_contents"]

    # The time and date of receiving the message, add  it to the email object
    timestamp = d.now().strftime("%Y-%m-%d %H:%M:%S")
    for destinations in destination:
        destin+=f"{destinations} "
    # end for loop

    #print the details of the email 
    print(f"An email from {sender} is sent to {destin} ")
    print(f"with a content length of {length} characters.")
    print(f"Title: {title}")
    print(f"Content Length: {length}")
    print(f"Content:\n{contents}")
    email_object["Time"]=timestamp
    #added time stamp to the new email object

    for new_des in destination:
        saveEmail(sender,new_des,title,email_object)
        # For each destination send email
    # end for loop
# end processEmail()
        

def saveEmail(sender,destination,title,email_object):
    destin_dir = os.path.join("client_emails", destination)
    # create a new folder, that contains the users
    os.makedirs(destin_dir, exist_ok=True)

    filename=f"{sender}_{title}.txt"
    # creates a file  that tracks for each user email
    added_file=os.path.join(destin_dir,filename)
    with open(added_file,'w') as file:
        # write json object to newly created file
        json.dump(email_object,file)
    # end with()
        
    print(f"Email has been sent successfully to {destination}\n")
# end saveEmail()


def displayEmail(clientSocket, serverPubKey, clientpubkey):
    '''
    Purpose: a helper function that displays any email's content in the server's
             inbox
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
    # send the client a message
    encrypted_message = encryptMessage("the server request email index",serverPubKey)
    clientSocket.send(encrypted_message)
    
    # recieve and decrypt the clients message then process req
    encrypted_email = clientSocket.recv(4096)
    decrypted_email = decipherMessage(encrypted_email,clientpubkey)
    
    email_view = getEmail(decrypted_email)
    encrypted_message = encrypted_message(email_view, serverPubKey)
    clientSocket.send(encrypted_email)
# end displayEmail()


def getEmail(emailReq):
    """
    Purpose: Process the email request then send the client the email, assumers
             correct emailReq contains valid information.
    Parameter: emailReq
    Return: emailDate
    """

    clientBox = emailReq["sender"]
    emailIndex = emailReq["emailIndex"]

    # need the clients username, and email index
    destinDIR = os.path.join("client_emails", clientBox)
    
    # List all .txt files in the user's directory
    emailFiles = \
        [file for file in os.listdir(destinDIR) if file.endswith('.txt')]
    
    selectedMail = emailFiles[emailIndex - 1]  # correct index for file
    emailPath = os.path.join(destinDIR, selectedMail)

    with open(emailPath, 'r') as email:
        emailDate = json.load(email)
    # end with
        
    return emailDate
# end getEmail()


def displayInbox(clientSocket, sym_key, client_username):
    '''
    Purpose: Send the client inbox emails' information sorted by received time and date
    Parameter: clientSocket - socket object for client communication
               sym_key - symmetric key for encryption
               client_username - username of the requesting client
    Return: none
    '''
    try:
        # Path to the directory containing inbox emails for the requesting client
        client_inbox_dir = os.path.join("client_emails", client_username)

        # Check if the client's inbox directory exists
        if not os.path.exists(client_inbox_dir):
            # If the directory does not exist, send an empty inbox email list
            inbox_emails = []
        else:
            # List all .txt files in the client's inbox directory
            email_files = [file for file in os.listdir(client_inbox_dir) if file.endswith('.txt')]

            # Initialize an empty list to store inbox email information
            inbox_emails = []

            # Iterate over each email file and extract relevant information
            for email_file in email_files:
                with open(os.path.join(client_inbox_dir, email_file), 'r') as email:
                    email_data = json.load(email)
                    inbox_emails.append({
                        "index": inbox_emails.index(email_data) + 1,
                        "sending_client": email_data["sender"],
                        "date_time": email_data["Time"],
                        "title": email_data["title"]
                    })

        # Sort inbox emails by received time and date
        inbox_emails = sorted(inbox_emails, key=lambda x: x["date_time"])

        # Prepare the message containing inbox email information
        message = json.dumps(inbox_emails)

        # Encrypt the message using AES symmetric encryption with the provided symmetric key
        cipher = AES.new(sym_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

        # Send the encrypted message to the client
        clientSocket.send(ciphertext)

        # Receive acknowledgment from the client
        acknowledgment = clientSocket.recv(1024).decode()
        if acknowledgment == "OK":
            print(f"Inbox emails sent to {client_username}.")
        else:
            print("Error: Client acknowledgment not received or invalid.")
        # end if statement
    except Exception as e:
        print("Error:", e)
    # end try & accept
# end displayInbox()  


def handleClient(clientSocket, addr):
    '''
    Purpose: Handles each client connection individually while calling helper
             functions
    Parameter: clientSocket - socket object for client communication
               addr - client address
    Return: none
    '''
    print(" TEST MESSAGE: IM HERE")

    # prints the IP address of the client trying to connect
    hostname = socket.gethostname()
    address = socket.gethostbyname(hostname)
    
    userIP = clientSocket.recv(1024).decode()

    print(" TEST MESSAGE: IM HERE 2")

    # checks if the user correctly typed the correct local IP address 
    if (userIP == address) or (userIP == "localhost"):
        print(f">> Connection established with {addr}")
    else:
        clientSocket.send(">> Wrong IP Address".encode())
        clientSocket.close()
    # end if statement
    
    # check if .pem files for the keys of the known users exist
    if not checkPemFilesExist():
        # If .pem files do not exist for all users, create them
        startCreatingUserKeys()
    else:
        print(">> Public and private key files already exist for all users.")
    # end if statement
        
    print(" TEST MESSAGE: IM HERE AFTER CHECKING IP ADDRESS")

    # load server's public key and client keys
    serverPubKey = loadServerPublicKey()
    print(" TEST MESSAGE: IM HERE AFTER GENERATING SERVER PUBLIC KEY")
    clientPubKeys = loadClientPublicKey()

    print(" TEST MESSAGE: IM HERE AFTER GENERATING PUBLIC KEYS")

    # sending welcome message and receiving user's credentials
    serverWelcomeMessage = ">>> Welcome to the Email Server <<<\n"
    clientSocket.send(serverWelcomeMessage.encode())

    # receives username and password from Client.py
    username = clientSocket.recv(1024).decode()
    password = clientSocket.recv(1024).decode()

    print(" TEST MESSAGE: IM HERE AFTER RECEIVING USERNAME AND PASSWORD")

    # checks if the user is authenticated by calling a helper function
    userINFO = loadUserInfo()
    if (username in userINFO and userINFO[username] == password):
        clientSocket.send(">> Authenticated".encode())
        print(f">> User {username} authenticated!")

        # Generate a symmetric key for the client
        symKey = generateSymmetricKey()

        # Send the symmetric key encrypted with the client's public key
        encryptedSymKey = encryptMessage(symKey, clientPubKeys[username])
        clientSocket.send(encryptedSymKey)

        # Print a message indicating the connection is accepted and a symmetric key is generated for the client
        print(f"Connection Accepted and Symmetric Key Generated for client: {username}")

        # receive email message NOT WORKING
        emailMSG = clientSocket.recv(1024).decode()

        # store email in user's folder NOT WORKING
        userFolder = os.path.join(os.getcwd(), username)
        if (not os.path.exists(userFolder) ):
            os.makedirs(userFolder)
        # end if statement
        with open(os.path.join(userFolder, "inbox.txt"), "a") as file:
            file.write(emailMSG + "\n")
        # end with
            
        # Encrypt email using client's public key
        if (username in clientPubKeys):
            encryptedMSG = encryptMessage(emailMSG.encode(), clientPubKeys[username])
            with open(os.path.join(userFolder, "encrypted_inbox.txt"), "ab") as file:
                file.write(encryptedMSG)
            print(f">> Email received from {username} and stored securely.")
        else:
            print(f">> Public key not found for user {username}. Email stored without encryption.")
        # end if statement
    else:
        clientSocket.send(">> Authentication failed!".encode())
        print(f"\t>> Authentication failed for {username}. Connection closed.")
    # end if statement
        
    # main communication loop to handle the client
    while True:
        try:
            # a string that holds the menu
            menu = ">> Select an operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n>> User's choice: "

            # TO DO: Encrypt 'menu' and send it to Client.py [DELETE COMMENT ONCE DONE]
            encryptedMenu = ""
            clientSocket.send(encryptedMenu)

            # receives an encrypted choice from the client
            encryptedChoice = clientSocket.recv(1024)
            # TO DO: Decrypt 'encryptedChoice' and process it [DELETE COMMENT ONCE DONE]
            choice = ""

            if (choice == '1'):
                # Handle sending email
                createEmail(clientSocket,serverPubKey,clientPubKeys[username])
            elif (choice == '2'):
                # Handle displaying inbox list
                displayInbox()
            elif (choice == '3'):
                # Handle displaying email contents
                displayEmail()
            elif (choice == '4'):
                # Terminate connection
                break
            # end if statement
        except Exception as e:
            print(f"Error: {e}")
            break
        # end try & accept
    # end major while loop
# end handleClient()


def main():
    '''
    Purpose: the main function that runs the server-side of the secure mail 
             transfer protocol and its available functions
    Parameter: none
    Return: none
    '''

    # Create the server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print(">> Error in server socket creation: ", e)
        sys.exit(1)
    # end try and accept
        
    # associate 13000 port number to the server socket
    try:
        serverSocket.bind(("localhost", 13000))
    except socket.error as e:
        print(">> Error in server socket binding: ", e)
        sys.exit(1)
    # end try and accept

    # makes Server.py handle 5 connections in its queue waiting for acceptance
    serverSocket.listen(5)
    # sets a timout for accepting connection (value is in seconds)
    serverSocket.settimeout(10)

    # prints out a successful message the server has been initialized
    print(">> The server is ready to accept connections and is listening.")
    
    while True:
        # accept a connection from a client
        clientSocket, addr = serverSocket.accept()

        # create a new thread to handle the client
        try:
            handleClient(clientSocket, addr)
        except socket.timeout:
            print(">> No clients attempting to connect...")

            # ask the user in the server for an action
            serverAction = input(">> Do you want to continue waiting for connections? (Y/N): ").strip().lower()

            # exit the server loop if user chooses to stop waiting
            if (serverAction.lower() == 'n'):
                print(">> Exiting server loop!")
                break  
            # end if stateemnt
        except Exception as e:
            print(f">> Error creating thread: {e}")
        # end try & accept
    # end while loop
    
    # closes the connection from the client
    clientSocket.close()
    print(">> Closing the datalink. Thank you for using the program")
# end main()
    
if __name__ == "__main__":
    main()
# end if statement