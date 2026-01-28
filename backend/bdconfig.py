import sqlite3
from sqlite3 import Error
from pathlib import Path

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

def createTable(connection, sqlCode):
    try:
        cursor = connection.cursor()
        cursor.execute(sqlCode)
    except Error as ex:
        print(ex)

def createAccount(connection, name, password):
    vsql = f"""INSERT INTO userLogin(user_name, password) VALUES (
            '{name}','{password}'
        )
    """

    try: 
        cursor = connection.cursor()
        cursor.execute(vsql)
        connection.commit()
        print("Register complete")
    except Error as ex:
        print(ex)

# Main
vcon = connectDB()
createAccount(vcon, "user1", "password")