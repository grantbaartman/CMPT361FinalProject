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
# TO DO: Figure out which library to encrypt/decrypt data [DELETE COMMENT ONCE DONE]
import hashlib
import json
import os
import socket
import sys

# TO DO: Code that loads Server.py's private key [DELETE COMMENT ONCE DONE]

# TO DO: COde that loads a file with all client usernames and passwords [DELETE COMMENT ONCE DONE]


def createEmail():
    '''
    Purpose: a helper function that lets the user create and send an email to
             the server
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
# end createEmail()
    

def displayEmail():
    '''
    Purpose: a helper function that displays any email's content in the server's
             inbox
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
# end displayEmail()


def displayInbox():
    '''
    Purpose: a helper function that displays the context of the server's inbox
             to the user
    Parameter: clientSocket - socket object for client communication
    Return: none
    '''
# end displayInbox()  


def handleClient(clientSocket, addr):
    '''
    Purpose: Handles each client connection individually while calling helper
             functions
    Parameter: clientSocket - socket object for client communication
               addr - client address
    Return: none
    '''
    # prints the IP address of the client trying to connect
    print(f">> Connection established with {addr}")

    # sending welcome message and receiving user's credentials
    serverWelcomeMessage = "=== Welcome to the Email System ===\n"
    clientSocket.send(serverWelcomeMessage.encode())

    # TO DO: Receive encrypted username and password from client [DELETE COMMENT ONCE DONE]
    #        Authenticate the user by accessing the file with all clients' username and passwords [DELETE COMMENT ONCE DONE]
    #        Code a successful message that the connection was accepted and a key was generated for the client [DELETE COMMENT ONCE DONE]
    #        While loop will be inside if statement if the user's authentication is valid (?) [DELETE COMMENT ONCE DONE]

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
                createEmail()
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

    print("Server is listening...")

    while True:
        # Accept client connection
        clientSocket, addr = serverSocket.accept()
        pid = os.fork()

        if pid == 0:  # Child process
            serverSocket.close()
            handleClient(clientSocket)
            break
        # end if statement
    # end while loop    
    serverSocket.close()
# end main()
    
if __name__ == "__main__":
    main()
# end if statement