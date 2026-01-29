import sqlite3
from sqlite3 import Error
from pathlib import Path
from hashlib import sha256
import os
from flask import jsonify


#No bd fnctions
def hashing(password ,salt):
    password_hash = sha256(salt + password.encode('utf-8')).hexdigest()
    return password_hash

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
        return True, 201, "CREATED"
    except Error as ex:
        print(ex)
        if str(ex) == 'UNIQUE constraint failed: user_login.name':
            return False, 209, "USERNAME_ALREADY_EXISTS"
        else:
            return False, 500, "unknown error"

def login(name, password, connection):
    vsql = f"""SELECT * FROM user_login WHERE name = '{name}'"""

    try:
        cursor = connection.cursor()
        cursor.execute(vsql)

        result = cursor.fetchone()

        #Recover the salt
        salt_hex = result[3]
        salt = bytes.fromhex(salt_hex)

        #Create the hash
        password_hash = hashing(password, salt)

        #Verify the Hash
        if(password_hash == result[2]):
            return True, 200, "Login successful"
        else:
            return False, 401, "Unauthorized"
    except Error as ex:
        print(ex)
        return False, 500, "unknown error"

    
def deleteAccount(name, connection):
    vsql = f"""DELETE FROM user_login WHERE name = '{name}'"""
    #LEMBRAR DE CONNECTION.COMMIT
    try:
        cursor = connection.cursor()
        cursor.execute(vsql)
        connection.commit()
        if cursor.rowcount == 0:
            return False, 404, "Account not found"
        else:
            return True, 200, "Account successfully deleted" 
    except Error as ex:
        print(ex)
        return False, 500, "unknown error"


# Main
vcon = connectDB()
#connection name passowrd

status = deleteAccount("user1",vcon)
print(status)