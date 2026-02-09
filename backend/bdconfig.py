import sqlite3
from sqlite3 import Error
from pathlib import Path
from hashlib import sha256
from os import urandom
from flask import request, jsonify
from flask import Flask
from flask_cors import CORS
from validate import validateCPF

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

    try:
        con = sqlite3.connect(db_path)
    except Error as ex:
        print(ex)
    return con

def createTable():
    file_dir = Path(__file__).resolve().parent
    db_path = file_dir / "database" / "user.db"
    if db_path.exists():
        print("db alredy exists")
        conn = connectDB()
    else:
        schema_path = file_dir / "database" / "schema.sql"
        schema_code = open(schema_path, encoding= "utf-8").read()

        conn = connectDB()
        conn.execute('PRAGMA foreign_keys = ON;')
        conn.executescript(schema_code)


@app.route('/createAccount', methods=["POST"])
def createAccount():

    data = request.get_json()

    name = data.get('name')
    password = data.get('password')
    # NONE for no info
    cpf = data.get('cpf')
    cnpj = data.get('cnpj') 
    email = data.get('email') 
    phone = data.get('phone')

    if(not name or not email):
        return jsonify({
                "status":"ERROR",
                "message": "MISSING FIELDS"
            }), 400

    #Checks if the user entered either a cpf or a cnpj
    #FOR FUTURE: VALIDATE EMAIL AND PHONE 
    if(not cpf and not cnpj):
        return jsonify({
            "status": "ERROR",
            "message": "Please provide a CPF or CNPJ"
        }), 400
    if (cpf):
        if(not validateCPF(cpf)):
            return jsonify({
                "status": "ERROR",
                "message": "Invalid CPF"
            }), 400

    #There's no way to verify the CNPJ


    salt = createSalt();

    vsql = """
        INSERT INTO user_login
        (email, password, salt, name, CNPJ, CPF, phone)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """


    try: 
        connection = connectDB()
        cursor = connection.cursor()
        cursor.execute(
            vsql,
            (
                email,
                hashing(password, salt),
                salt.hex(),
                name,
                cnpj, 
                cpf, 
                phone
            )
        )
        connection.commit()
        return jsonify({
                "status": "SUCCESS",
                "message": "CREATED"
            }), 201
    except Error as ex:
        print(ex)
        return jsonify({
            "status":"ERROR",
            "message":"SOME DATA IS ALREADY IN USE"
        }), 409
        pass
            
        
    finally:
        connection.close()
        


def authenticateAccount(name, password):

    if(not name or not password):
        return 400

    connection = connectDB()

    vsql = "SELECT * FROM user_login WHERE name = ?"

    try:
        cursor = connection.cursor()
        cursor.execute(vsql,(name,))

        result = cursor.fetchone()
        
        if result == None:
            return 401
        #Recover the salt
        salt_hex = result[2]
        salt = bytes.fromhex(salt_hex)

        #Create the hash
        password_hash = hashing(password, salt)

        #Verify the Hash
        if(password_hash == result[1]):
            return 200
        else:
            return 401
    except Error as ex:
        print(ex)
        return 500

    finally:
        connection.close()

@app.route('/Login', methods=['POST'])
def Login():
    data = request.json
    name = data.get("name")
    password = data.get("password")
    
    authenticateStatus = authenticateAccount(name, password)

    match(authenticateStatus):
        case 200:
            return jsonify({
                "status": "SUCCESS",
                "message": "LOGIN SUCCESSFUL"
            }, 200)
        case 401:
            return jsonify({
                "status": "ERROR",
                "message": "Unauthorized"
            }), 401
        case 400:
            return jsonify({
                "status":"ERROR",
                "message": "MISSING FIELDS"
            }), 400


@app.route('/DeleteAccount', methods=['DELETE'])
def deleteAccount():

    data = request.json

    name = data.get('name')
    password = data.get('password')

    vsql = "DELETE FROM user_login WHERE name = ?"
    
    AutenticateStatus = authenticateAccount(name, password)

    match(AutenticateStatus):
        case 200:
            try:
                connection = connectDB()
                cursor = connection.cursor()
                cursor.execute(vsql, (name,))
                connection.commit()
                return jsonify({
                    "status": "SUCCESS",
                    "message": "Account successfully deleted"
                }), 204
            except Error as ex:
                print(ex)
                return jsonify({
                    "status": "ERROR",
                    "message": "INTERNAL-ERROR"
                }), 500
            finally:
                connection.close()
        case 401:
            return jsonify({
                "status": "ERROR",
                "message": "Unauthorized"
            }), 401
        

@app.route("/UpdateAccount", methods=["PUT"])
def updateAccount():

    data = request.json

    oldName = data.get('oldName')
    oldPassword = data.get('oldPassword')
    newName = data.get('newName')
    newPassword = data.get('newPassword')

    authenticateStatus = authenticateAccount(oldName, oldPassword)
    print(authenticateStatus)
    if authenticateStatus[1] == 200:
        try:
            connection = connectDB()
            cursor = connection.cursor()

            #Params list: newName and NewPassword
            params = []
            # SQL CommandsList
            fields = []
            if(newName is not None and not newName == oldName):
                fields.append(f"name = ?")
                params.append(newName)

            if(newPassword is not None and not newPassword == oldPassword):
                newSalt = createSalt()
                newHash = hashing(newPassword, newSalt)

                fields.append(f"password = ?")
                params.append(newHash)

                fields.append(f"salt = ?")
                params.append(newSalt.hex())

            if not fields:
                return jsonify({
                    "status": "ERROR",
                    "message": "Nothing to update"
                }), 400

            params.append(oldName)

            vsql = f"""
                    UPDATE user_login
                    SET {", ".join(fields)}
                    WHERE name = ?
                """
            print(vsql)
            cursor.execute(vsql, tuple(params))
            
            connection.commit()
            return jsonify({
                "status": "SUCCESS",
                "message": "Updated successfully"
            }), 200
        except Error as ex:
            print(ex)
            return jsonify({
                "status": "ERROR",
                "message": "INTERNAL-ERROR"
            }), 500
        finally:
            connection.close()
    else:
        return authenticateStatus
    
# 

# Main

#connection name passowrd


if __name__ == "__main__":
    app.run(debug=True)


# C - CREATE = createAccount() v
# R - READ = authenticateAccount()
# U - UPDATE = updateUser()
# D - DELETE = deleteAccount()