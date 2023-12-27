#!/bin/python3


from cryptography.fernet import Fernet
import sqlite3
from getpass import getpass
from passlib.context import CryptContext
from prettytable import PrettyTable
import sys
from colorama import init, Fore

init(autoreset=True)  # Initialize colorama

sys.tracebacklimit = 0

# Success and error message colors
SUCCESS_COLOR = Fore.GREEN
ERROR_COLOR = Fore.RED

# Create a CryptContext instance with a suitable algorithm
pwd_context = CryptContext(schemes=["bcrypt"])

# Database initialization
conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        master_password TEXT NOT NULL
    )
''')

# Create passwords table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        website_name TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (ID)
    )
''')

conn.commit()

# Key generation for Fernet
def generate_key(master_password):
    kdf = Fernet.generate_key()
    return Fernet(kdf)

# User registration
def register():
    username = input("Enter your username: ")
    master_password = getpass("Enter your master password: ")

    # Hash the master password using passlib
    hashed_master_password = pwd_context.hash(master_password)

    cursor.execute("INSERT INTO users (username, master_password) VALUES (?, ?)", (username, hashed_master_password))
    conn.commit()
    print(SUCCESS_COLOR + "Registration successful!" + Fore.RESET)

# User login
def login():
    username = input("Enter your username: ")
    master_password = getpass("Enter your master password: ")

    cursor.execute("SELECT ID, master_password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if user:
        user_id, stored_hashed_password = user

        # Verify the password using passlib's verify method
        if pwd_context.verify(master_password, stored_hashed_password):
            print(SUCCESS_COLOR + "Login successful!" + Fore.RESET)
            return user_id
        else:
            print(ERROR_COLOR + "Invalid master password." + Fore.RESET)
    else:
        print(ERROR_COLOR + "User not found." + Fore.RESET)

    return None

# Main program
while True:
    action = input("Do you want to register (R) or login (L)? ").upper()

    if action == "R":
        register()
    elif action == "L":
        user_id = login()
        if user_id is not None:
            break
    else:
        print("Invalid choice. Please enter 'R' or 'L'.")

# Menu
while True:
    print("\nMenu:")
    print("1. Show saved passwords")
    print("2. Add password")
    print("3. Modify password")
    print("4. Delete password")
    print("5. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        cursor.execute("SELECT website_name, username, password FROM passwords WHERE user_id=?", (user_id,))
        passwords = cursor.fetchall()

        if passwords:
            table = PrettyTable(["Website", "Username", "Password"])
            for website, username, password in passwords:
                table.add_row([website, username, password])

            print(table)
        else:
            print(ERROR_COLOR + "No passwords found for the user." + Fore.RESET)


    elif choice == "2":
        website_name = input("Enter website name: ")
        username = input("Enter username: ")
        password = input("Enter password: ")

        cursor.execute("INSERT INTO passwords (user_id, website_name, username, password) VALUES (?, ?, ?, ?)",
                       (user_id, website_name, username, password))
        conn.commit()
        print(SUCCESS_COLOR + "Password added successfully."  + Fore.RESET)

    elif choice == "3":
        website_name = input("Enter website name for which you want to modify (update) the password: ")
        field_to_modify = input("What do you want to modify (username/password)? ").lower()

        if field_to_modify == "username":
            new_username = input("Enter the new username: ")
            cursor.execute("UPDATE passwords SET username=? WHERE user_id=? AND website_name=?", (new_username, user_id, website_name))
        elif field_to_modify == "password":
            new_password = input("Enter the new password: ")
            cursor.execute("UPDATE passwords SET password=? WHERE user_id=? AND website_name=?", (new_password, user_id, website_name))
        else:
            print(ERROR_COLOR + "Invalid choice." + Fore.RESET)

        conn.commit()
        print(SUCCESS_COLOR + "Password modified successfully." + Fore.RESET)

    elif choice == "4":
        website_name = input("Enter website name for which you want to delete the password: ")
        cursor.execute("DELETE FROM passwords WHERE user_id=? AND website_name=?", (user_id, website_name))
        conn.commit()
        print(SUCCESS_COLOR + "Password deleted successfully." + Fore.RESET)

    elif choice == "5":
        print("Exiting the password manager. Goodbye!")
        break

    else:
        print(ERROR_COLOR + "Invalid choice. Please enter a number between 1 and 5." + Fore.RESET)

conn.close()
