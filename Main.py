from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import json
import os
import base64
import tempfile

# initialization=====================================================================
{
  "DBInfo": { "Password": "", "Key": "" },
  "detail": [
    { "Username": "...", "Password": "...", "Note": "..." }
  ]
}

DB_DIR = "./database"

# buat salt dan hash data
# panggil kdf buat encrypt password
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_200_000,
)
# DAFTAR DEF=====================================================================
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
    dbPasswordInput = getpass.getpass("Enter database Password: ")

    # password di encrypt
    DBkey = base64.urlsafe_b64encode(kdf.derive(dbPasswordInput.encode()))

    # input password di encrypt dengan key dari variabel DBkey 
    fernet = Fernet(DBkey)
    encrypted_password = fernet.encrypt(dbPasswordInput.encode()).decode()

    data = {
        "DBInfo": {
            "Password": encrypted_password,
            "Key": DBkey.decode()
        },
        "detail": []
    }

    # Cek kalau directori nya ada ato gk
    os.makedirs("./database", exist_ok=True)

    #seinget gw ini buat file sementara biar gk korup, trus di rename jadi yang bener
    dirpath = os.path.dirname(os.path.abspath(f"./database/{dbNameInput}.json")) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirpath, prefix="dbtmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmpf:
            json.dump(data, tmpf, indent=4, ensure_ascii=False)
            tmpf.flush()
            os.fsync(tmpf.fileno())
        os.replace(tmp_path, f"./database/{dbNameInput}.json")
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    main_menu()

def atomic_write(path, obj):
    dirpath = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirpath, prefix="dbtmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            json.dump(obj, tf, indent=4, ensure_ascii=False)
            tf.flush()
            os.fsync(tf.fileno())
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

def load_database():
    list_databases()

    dbNameInput = input("Enter database name to load: ").strip()
    if not dbNameInput:
        print("Database name cannot be empty.")
        load_database()

    if not os.path.exists(DB_DIR):
        print("No databases found. Please create a new database first.")
        main_menu()

    db_path = os.path.join(DB_DIR, f"{dbNameInput}.json")
    if not os.path.exists(db_path):
        print("Database not found.")
        load_database()

    dbKeyInput = getpass.getpass("Enter Password: ")
    if not dbKeyInput:
        print("Password cannot be empty.")
        load_database()

    #load database dan cek korup ato gk
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            dbData = json.load(f)
    except json.JSONDecodeError:
        print("Database file is corrupted or invalid JSON.")
        main_menu()

    # password database dicoba di decrypt dan di cek benar atau gk
    try:
        encrypted_password = dbData["DBInfo"]["Password"]
        db_key = dbData["DBInfo"]["Key"].encode()
        fernet = Fernet(db_key)
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
    except Exception:
        print("Error reading DB info or decrypting password.")
        main_menu()

    if dbKeyInput != decrypted_password:
        print("Incorrect password.")
        main_menu()

    print("Database loaded successfully.")

    # buat cek kelengkapan dan kebenaran file json
    if "detail" not in dbData or dbData["detail"] is None:
        dbData["detail"] = []
    elif not isinstance(dbData["detail"], list):
        existing = dbData.get("detail")
        dbData["detail"] = [existing] if existing else []

    def inner_menu():
        while True:
            print("\n1 : New Entry")
            print("2 : Edit Entry")
            print("3 : List Entries")
            print("4 : DELETE ENTRY")
            print("5 : EXIT")
            option = input("Select an option: ").strip()

            if option == "1":
                add_entry(dbData, db_path)
            elif option == "2":
                edit_entry(dbData, db_path)
            elif option == "3":
                list_entries(dbData)
            elif option == "4":
                delete_entry(dbData, db_path)
            elif option == "5":
                return
            else:
                print("Invalid option.")
                inner_menu()
    inner_menu()
    
def add_entry(dbData, db_path, check_duplicate=True):
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    password = getpass.getpass("Enter password: ")
    note = input("Enter note (optional): ").strip()

    # mengambil key dari json yang dipilih
    db_key = dbData["DBInfo"]["Key"].encode()
    fernet = Fernet(db_key)

    # Encrypt
    enc_username = fernet.encrypt(username.encode()).decode()
    enc_password = fernet.encrypt(password.encode()).decode()
    enc_note = fernet.encrypt(note.encode()).decode()

    new_entry = {"Username": enc_username, "Password": enc_password, "Note": enc_note}

    # duplicate check
    if check_duplicate:
        for item in dbData["detail"]:
            try:
                existing_username = fernet.decrypt(item.get("Username", "").encode()).decode()
            except Exception:
                existing_username = ""
            if existing_username == username:
                print(f"Entry for username {username!r} already exists.")
                return

    dbData["detail"].append(new_entry)
    atomic_write(db_path, dbData)
    print("New entry added.")

# Placeholder stubs you should implement
def list_databases():
    # show files in DB_DIR
    if not os.path.exists(DB_DIR):
        print("No database directory.")
        return
    files = [f for f in os.listdir(DB_DIR) if f.endswith(".json")]
    if not files:
        print("No databases found.")
    else:
        for f in files:
            print("-", f)

def edit_entry(dbData, db_path):
    print("Edit entry not implemented yet.")

def list_entries(dbData):
    if not dbData["detail"]:
        print("No entries.")
        return
    db_key = dbData["DBInfo"]["Key"].encode()
    fernet = Fernet(db_key)
    for i, item in enumerate(dbData["detail"], start=1):
        try:
            username = fernet.decrypt(item.get('Username', '').encode()).decode()
        except Exception:
            username = "<decryption error>"
        try:
            password = fernet.decrypt(item.get('Password', '').encode()).decode()
        except Exception:
            password = "<decryption error>"
        try:
            note = fernet.decrypt(item.get('Note', '').encode()).decode()
        except Exception:
            note = "<decryption error>"
        print(f"{i}. Username: {username}  Password: {password}  Note: {note}")

def delete_entry(dbData, db_path):
    print("Delete entry not implemented yet.")

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
#Mulai Program=====================================================================

main_menu()
# print(password)
# key = Fernet.generate_key()
# f = Fernet(key)
# token = f.encrypt(b"my deep dark secret")
# token
# b'...'
# f.decrypt(token)
# b'my deep dark secret'