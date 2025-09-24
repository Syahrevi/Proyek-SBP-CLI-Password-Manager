from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import json
import os
import base64

data = {
    "DBInfo": {
        "Password": "",
        "Key": ""
    },
    "detail": [
    { "Username": "", "Password": "", "Note": "" }
  ]
    }

salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_200_000,
)

def main_menu():
    print("1 : NEW DATABASE")
    print("2 : LOAD DATABASE")
    option = input("Select an option: ")  
    if option == "1":
        create_database()
    elif option == "2":
        load_database()

def create_database():
    dbNameInput = input("Enter database name: ")
    dbPasswordInput = input("Enter database Password: ")

    key = base64.urlsafe_b64encode(kdf.derive(dbPasswordInput.encode()))
    DBkey = Fernet.generate_key()

    # Encrypt the password using Fernet
    fernet = Fernet(DBkey)
    encrypted_password = fernet.encrypt(dbPasswordInput.encode()).decode()

    data["DBInfo"]["Password"] = encrypted_password
    data["DBInfo"]["Key"] = DBkey.decode()

    os.makedirs("./database", exist_ok=True)
    with open(f"./database/{dbNameInput}.json", "w") as dbFile:
        json.dump(data, dbFile, indent=4)
    main_menu()

def load_database():
        list_databases()
        def inner_menu():
                print("1 : New Entry")
                print("2 : Edit Entry")
                print("3 : list Entries")
                print("4 : DELETE ENTRY")
                print("5 : EXIT")

                option = input("Select an option: ")
                if option == "1":
                    add_entry(dbNameInput)
                elif option == "2":
                    pass
                elif option == "3":
                    pass
                elif option == "4":
                    pass
                elif option == "5":
                    main_menu()
                else:
                    print("Invalid option.")

        def add_entry(dbNameInput):
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            note = input("Enter note (optional): ")
            data = {
                "detail": {
                    "Username": username,
                    "Password": password,
                    "Note": note
                }
            }
        
        dbNameInput = input("Enter database name to load: ")
        if not dbNameInput:
            print("Database name cannot be empty.")
            return
        elif not os.path.exists("./database"):
            print("No databases found. Please create a new database first.")
            return
        
        dbKeyInput = getpass.getpass("Enter Password: ")
        if not dbKeyInput:
            print("Password cannot be empty.")
            return

        db_path = f"./database/{dbNameInput}.json"
        if os.path.exists(db_path):
            with open(db_path, "r") as dbFile:
                dbData = json.load(dbFile)
                encrypted_password = dbData["DBInfo"]["Password"]
                db_key = dbData["DBInfo"]["Key"].encode()
                fernet = Fernet(db_key)
                try:
                    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                    if dbKeyInput != decrypted_password:
                        print("Incorrect password.")
                        load_database()
                    elif dbKeyInput == decrypted_password:
                        print("Database loaded successfully.")
                        inner_menu()
                except Exception:
                    print("Error decrypting password.")
        else:
            print("Database not found.")

        with open(f"./database/{dbNameInput}.json", "a") as dbFile:
            json.dump(data, dbFile, indent=4)

def list_databases():
        files = os.listdir("./database")
        db_files = [f for f in files if f.endswith('.json')]
        if db_files:
            print("Available Databases:")
            for db in db_files:
                print(f"- {db[:-5]}")
        else:
            print("No databases found.")
        
main_menu()
# print(password)
# key = Fernet.generate_key()
# f = Fernet(key)
# token = f.encrypt(b"my deep dark secret")
# token
# b'...'
# f.decrypt(token)
# b'my deep dark secret'