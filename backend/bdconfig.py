import sqlite3
from sqlite3 import Error
from pathlib import Path
from hashlib import sha256
import os

# this function create a database connection
def connectDB():
    file_dir = Path(__file__).resolve().parent
    db_path = file_dir / "database" / "user.db"

    con = None

    try:
        con = sqlite3.connect(db_path)
    except Error as ex:
        print(ex)
    return con

def createTable(connection):
    sqlcode = """CREATE TABLE user_login(
    id_user INTEGER PRIMARY KEY,
    name TEXT(30) NOT NULL UNIQUE,
    password CHAR(64) NOT NULL,
    salt CHAR(32) NOT NULL
    );
    """
    try:
        cursor = connection.cursor()
        cursor.execute(sqlcode)
    except Error as ex:
        print(ex)

def hashing(password ,salt):
    password_hash = sha256(salt + password.encode('utf-8')).hexdigest()
    return password_hash

def createAccount(name, password, connection):
    salt = os.urandom(16)
    salt_hex = salt.hex() # para reconstruir o salt "salt = bytes.fromhex(salt_hex)"

    vsql = f"""INSERT INTO user_login(name, password, salt) VALUES (
            '{name}','{hashing(password, salt)}','{salt_hex}' 
        )
    """

    try: 
        cursor = connection.cursor()
        cursor.execute(vsql)
        connection.commit()
        print("Register complete")
    except Error as ex:
        print(ex)

def login(name, password, connection):
    cursor = connection.cursor()
    vsql = f"""SELECT * FROM user_login WHERE name = '{name}'"""
    cursor.execute(vsql)

    result = cursor.fetchone()

    #Recover the salt
    salt_hex = result[3]
    salt = bytes.fromhex(salt_hex)

    #Create the hash
    password_hash = hashing(password, salt)

    #Verify the Hash
    if(password_hash == result[2]):
        print("Login efetuado com sucesso")
    else:
        print("Senha ou Usuário incorreto")
    

# Main
vcon = connectDB()
#connection name passowrd
login('user1', 'password1', vcon)