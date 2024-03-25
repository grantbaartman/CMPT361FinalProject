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


# TO DO: Code that loads Server's Public key [DELETE COMMENT ONCE DONE]

# TO DO: COde that loads the Client's Public and Private keys (?) [DELETE COMMENT ONCE DONE]

# get server IP address fronm user
serverIP = input(">> Enter the server's IP address: ")

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

    # TO DO: Encrypt the username and password with server's public key [DELETE COMMENT ONCE DONE]
    encryptedData = ""
    clientSocket.send(encryptedData)


    # receive symmetric key from server and decrypt it to 'symetra'
    encryptedSymetra = clientSocket.recv(1024)
    # TO DO: Decrypt the encryptedSymetra with client's private key [DELETE COMMENT ONCE DONE]
    symetra = ""

    return clientSocket, symetra
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
        clientSocket, symetra = authenticateWithServer()

        while True:
            # receive the  server's menu options
            encryptedMenu = clientSocket.recv(1024)
            # TO DO: Decrypt the encryptedMenu with the acquired symetra key [DELETE COMMENT ONCE DONE]
            menu = ""
            userChoice = input(menu)

            # gets, encrypts and sends the user's choice to the server
            # TO DO: Encrypt userChoice with acquired symetra key [DELETE COMMENT ONCE DONE]
            encryptedChoice = ""
            clientSocket.send(encryptedChoice)

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
    
if __name__ == "__main__":
    main()
# end if statement