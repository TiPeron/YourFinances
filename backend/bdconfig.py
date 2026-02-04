import sqlite3
from sqlite3 import Error
from pathlib import Path
from hashlib import sha256
from os import urandom
from flask import request, jsonify
from flask import Flask
from flask_cors import CORS

# name, password, CNPJ ou cpf, email, telefone 

app = Flask(__name__)
CORS(app)

#No bd functions

#Create a new salt
#Return a hexadecimal element
def createSalt():
    salt = urandom(16)
    return salt

#Create a hash in hexadecimal
def hashing(password:str ,salt:bytes):
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

@app.route('/createAccount', methods=["POST"])
def createAccount():

    data = request.get_json()
    
    name = data["name"]
    password = data["password"]

    salt = createSalt();

    vsql = f"""INSERT INTO user_login(name, password, salt) VALUES (
            '{name}','{hashing(password, salt)}','{salt.hex()}' 
        )
    """

    try: 
        connection = connectDB()
        cursor = connection.cursor()
        cursor.execute(vsql)
        connection.commit()
        return jsonify({"status": "CREATED"}), 201
    except Error as ex:
        if str(ex) == 'UNIQUE constraint failed: user_login.name':
            return jsonify({"status": "USERNAME_ALREADY_EXISTS"}), 409
        else:
            print(ex)
            return jsonify({"status": "UNKNOWN_ERROR"}), 500
        


def authenticateAccount(name, password, connection):
    vsql = f"""SELECT * FROM user_login WHERE name = '{name}'"""

    try:
        cursor = connection.cursor()
        cursor.execute(vsql)

        result = cursor.fetchone()
        if result == None:
            return False, 401, "Unauthorized"
        #Recover the salt
        salt_hex = result[3]
        salt = bytes.fromhex(salt_hex)

        #Create the hash
        password_hash = hashing(password, salt)

        #Verify the Hash
        if(password_hash == result[2]):
            return jsonify({
                "status": "SUCCESS",
                "message": "Login successful"
            }), 200
        else:
            return jsonify({
                "status": "ERROR",
                "message": "Unauthorized"
            }), 401
    except Error as ex:
        print(ex)
        return jsonify({
            "status": "ERROR",
            "message": "Unknown error"
        }), 500


def deleteAccount(id, connection):
    vsql = f"""DELETE FROM user_login WHERE id_user = '{id}'"""
    #LEMBRAR DE CONNECTION.COMMIT
    try:
        cursor = connection.cursor()
        cursor.execute(vsql)
        connection.commit()
        if cursor.rowcount == 0:
            return jsonify({
                "status": "ERROR",
                "message": "Account not found"
            }), 404
        else:
            return jsonify({
                "status": "SUCCESS",
                "message": "Account successfully deleted"
            }), 200
    except Error as ex:
        print(ex)
        return jsonify({
            "status": "ERROR",
            "message": "Unknown error"
        }), 500

def updateUser(id, oldPassword, newName, newPassword, connection):
    vsql = f"""SELECT name FROM user_login WHERE id_user = '{id}'"""
    try:

        cursor = connection.cursor()
        cursor.execute(vsql)

        result = cursor.fetchone()[0]

        status = authenticateAccount(result, oldPassword, connection)

        if status[0]:
            #Params list: newName and NewPassword
            params = []
            # SQL CommandsList
            fields = []
            if(newName is not None):
                fields.append(f"name = '{newName}'")
                params.append(newName)

            if(newPassword is not None):
                newSalt = createSalt()
                newHash = hashing(newPassword, newSalt)

                fields.append(f"password = '{newHash}'")
                params.append(newPassword)

                fields.append(f"salt = '{newSalt.hex()}'")

            if not fields:
                return jsonify({
                    "status": "ERROR",
                    "message": "Nothing to update"
                }), 400
            
            print(", ".join(fields))

            vsql = f"""
                    UPDATE user_login
                    SET {", ".join(fields)}
                    WHERE id_user = {id}
                """
            cursor.execute(vsql)
            connection.commit()
            return jsonify({
                "status": "SUCCESS",
                "message": "Updated successfully"
            }), 200
        else:
            return status
    except Error as ex:
        print(ex)
        return jsonify({
            "status": "ERROR",
            "message": "Unknown error"
        }), 500
# 

# Main

#connection name passowrd

# status = authenticateAccount('teste3', '12345', connection)
# print(status)

if __name__ == "__main__":
    app.run(debug=True)
    
# C - CREATE = createAccount() v
# R - READ = authenticateAccount()
# U - UPDATE = updateUser()
# D - DELETE = deleteAccount()