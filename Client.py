# ------------------------------------------------------------------------------
# Integrity Pledge:
# I declare that the work is being submitted is my own
# It was completed in accordance with MacEwan's Academic Integrity Policy
# Author(s): Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# ------------------------------------------------------------------------------
# Name of Group Members: Ayub Haji, Christian Villafranca, Grant Baartman, 
#                        Sankalp Shrivastav, and Tarik Unal
# Program: Client.py
# ------------------------------------------------------------------------------
# Purpose: The program simulates a secure mail transfer protocol using client 
# and server programs in a UNIX-like environment.This program interfaces 
# seamlessly with the server, adhering to the specified protocol. Client.py must
# have implemented security measures to maintain the confidentiality and 
# integrity of transmitted data. The program also participates in identifying 
# and addressing potential vulnerabilities in the protocol, enhancing its 
# security posture.
# ------------------------------------------------------------------------------

# importing crucial libraries to simulate a secure mail transfer protocol
import os
import socket
import sys
from datetime import datetime as d
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import json


def loadServerPublicKey():
    '''
    Purpose: Load the server's public key from file server_public.pem
    Return: serverPublicKey - the loaded server's public key object
    '''
    try:
        with open("server_public.pem", "r") as file:
            serverPublicKey = RSA.import_key(file.read())
        return serverPublicKey
    except Exception as e:
        print(f"Error loading server's public key from file: {e}")
        return None


def loadClientPublicKey(clientPublicKeyFile):
    '''
    Purpose: Load a private key from a file
    Parameter: privateKeyFile - the file path of the private key
    Return: privateKey - the loaded private key object
    '''
    try:
        with open(clientPublicKeyFile, "r") as file:
            publicKey = RSA.import_key(file.read())
        return publicKey
    except Exception as e:
        print(f"Error loading public key from file {clientPublicKeyFile}: {e}")
        return None
    
def loadClientPrivateKey(clientPrivateKeyFile):
    '''
    Purpose: Load a private key from a file
    Parameter: privateKeyFile - the file path of the private key
    Return: privateKey - the loaded private key object
    '''
    try:
        with open(clientPrivateKeyFile, "r") as file:
            privateKey = RSA.import_key(file.read())
        return privateKey
    except Exception as e:
        print(f"Error loading private key from file {clientPrivateKeyFile}: {e}")
        return None
    
# get server IP address fronm user
serverIP = input(">> Enter the server's IP address: ")


    
def decryptSymmetricKey(encryptedSymmetricKey, clientPrivateKey):
    '''
    Purpose: Decrypt the encrypted symmetric key received from the server
    Parameter: encryptedSymmetricKey - The encrypted symmetric key
               clientPrivateKey - The client's private key
    Return: symmetricKey - The decrypted symmetric key
    '''
    # Create a cipher object for decryption
    cipher_rsa = PKCS1_OAEP.new(clientPrivateKey)

    # Decrypt the symmetric key
    symmetricKey = cipher_rsa.decrypt(encryptedSymmetricKey)

    return symmetricKey

def authenticateWithServer():
    '''
    Purpose: a helper function that tries to connect and authenticate the user
             to the sercure Email server
    Parameter: none
    Return: clientSocket - the vital connection to the server
            symetra - the key that can decrypt encrypted messages from the server
    '''
    # create a client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print(">> Error in client socket creation: ",e)
        sys.exit(1)    
    # end try & except

    try:
        # client tries to connect with the server
        clientSocket.connect(("localhost", 13000))
    except socket.error as e:
        print(">> An error occured in the client-side:'", e)
        clientSocket.close()
        sys.exit(1)
    # end try & except()

    # get username and password from user input
    username = input(">> Enter your username: ")
    password = input(">> Enter your password: ")
    
    # Load server's public key
    serverPubKey = loadServerPublicKey()

    # Encrypt username and password
    encryptedUsername = encrypt(username, serverPubKey)
    encryptedPassword = encrypt(password, serverPubKey)

    # Send encrypted username and password to server
    clientSocket.send(encryptedUsername)
    clientSocket.send(encryptedPassword)

    # receive symmetric key from server and decrypt it to 'symetra'
    encryptedSymetra = clientSocket.recv(1024)
    clientPrivateKeyFile = f"{username}_private.pem"
    clientPrivateKey = loadClientPrivateKey(clientPrivateKeyFile)

    sym_key = decryptSymmetricKey(encryptedSymetra, clientPrivateKey)

    okMessage = "OK"

    encryptedMessage = encrypt(okMessage)
    clientSocket.send(encryptedMessage)
    

    return clientSocket, sym_key
# end authenticateWithServer()

def main():
    '''
    Purpose: the main function that runs the server-side of the secure mail 
             transfer protocol and its available functions
    Parameter: none
    Return: none
    '''
    try:
        # call a helper function to authenticate to the server
        clientSocket, sym_key = authenticateWithServer()

        while True:
            # receive the  server's menu options
            encryptedMenu = clientSocket.recv(1024)
            menu = decrypt(encryptedMenu, sym_key)
            userChoice = input(menu)

        
            # gets, encrypts and sends the user's choice to the server
            # TO DO: Encrypt userChoice with acquired symetra key [DELETE COMMENT ONCE DONE]
            encryptedChoice = encrypt(userChoice, sym_key)
            clientSocket.send(encryptedChoice)
            if(userChoice=='1'):
                send_email(clientSocket, sym_key)
                return
            
            if (userChoice == '3'):
                view_email(clientSocket)
                return

            # terminate the connection if the user chooses so
            if (userChoice == '4'):
                break
            # end if statement
        # end while loop
        
        # closes the connection to the server
        clientSocket.close()
    except Exception as e:
        print(f">> Error: {e}")
    # end try & accept
# end main()
        
def send_email(clientSocket, sym_key):
    sender_username = input("Enter your username: ")
    destination_usernames = input("Enter destination usernames separated by ';': ")
    destination_usernames = destination_usernames.split(';')
    email_title = input("Enter email title: ")
    message_contents = input("Enter message contents: ")
    content_length = len(message_contents)
    email_message = {
        "sender": sender_username,
        "destinations": destination_usernames,
        "title": email_title,
        "content_length": content_length,
        "message_contents": message_contents
    }

    # Encrypt email message
    encrypted_email = encrypt(json.dumps(email_message), sym_key)
    clientSocket.send(encrypted_email)
    print("The message is sent to the server.")

def view_email(clientSocket, sym_key):

    client_username = input("Enter your username: ")
    validIndex = False

    while not validIndex:
        email_index = input("Enter the email index you wish to view: ")

        try:
            email_index = int(email_index)
            validIndex = True
        except:
            continue
    
    email_rerquest = {
        "sender": client_username,
        "emailIndex": email_index
    }
    
    # Encrypt email message and send it
    encrypted_email = encrypt(json.dumps(email_rerquest), sym_key)
    clientSocket.send(encrypted_email)

    # recieve and decrypt the clients message then process req
    encrypted_email=clientSocket.recv(4096)

    # TODO: display email

def displayInbox(clientSocket, sym_key):
    '''
    Purpose: Receive and display inbox emails' information from the server
    Parameter: clientSocket - socket object for client communication
               sym_key - symmetric key for decryption
    Return: none
    '''
    try:
        # Receive and decrypt inbox email information from the server
        info = clientSocket.recv(1024)
        inbox_info = decrypt(info, sym_key)

        # Convert the decrypted JSON string back to a Python list of dictionaries
        inbox_emails = json.loads(inbox_info)

        # Display inbox email information
        if inbox_emails:
            print("Inbox emails:")
            for email in inbox_emails:
                print(f"Index: {email['index']}, Sender: {email['sending_client']}, Date/Time: {email['date_time']}, Title: {email['title']}")
        else:
            print("Inbox is empty.")
    except Exception as e:
        print("Error:", e)



def encryptSymKey(data, publicKey):
    '''
    Purpose: Encrypt data using RSA public key
    Parameters: data - the data to be encrypted
                publicKey - the RSA public key object
    Return: encryptedData - the encrypted data
    '''
    try:
        cipher = PKCS1_OAEP.new(publicKey)
        encryptedData = cipher.encrypt(data.encode())
        return encryptedData
    except Exception as e:
        print(f"Error encrypting data: {e}")
        return None
    

def encrypt(data, sym_key):
    '''
    Purpose: Encrypt data using AES symmetric key
    Parameters: data - the data to be encrypted
                sym_key - the symmetric key
    Return: encryptedData - the encrypted data
    '''
    try:
        # Generate a random initialization vector (IV)
        iv = get_random_bytes(AES.block_size)

        # Create AES cipher object
        cipher = AES.new(sym_key, AES.MODE_CBC, iv)

        # Pad the data to be multiple of 16 bytes (AES block size)
        padded_data = pad(data.encode(), AES.block_size)

        # Encrypt the data
        encrypted_data = cipher.encrypt(padded_data)

        # Return IV + encrypted data
        return iv + encrypted_data
    except Exception as e:
        print(f"Error encrypting data: {e}")
        return None
    

def decrypt(data, sym_key):
    '''
    Purpose: Decrypt data using AES symmetric key
    Parameters: data - the data to be decrypted
                sym_key - the AES symmetric key
    Return: decryptedData - the decrypted data
    '''
    try:
        # Initialize AES cipher in CBC mode with sym_key
        cipher = AES.new(sym_key, AES.MODE_CBC, iv=data[:AES.block_size])

        # Decrypt the data
        decryptedData = cipher.decrypt(data[AES.block_size:])
        
        # Remove padding
        decryptedData = unpad(decryptedData, AES.block_size)
        return decryptedData.decode()
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None
 
    
if __name__ == "__main__":
    main()
# end if statement