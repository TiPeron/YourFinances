from pathlib import Path
from sqlite3 import connect
from sqlite3 import Error


base_dir = Path(__file__).resolve().parent
db_path = base_dir / "user.db"
schema_path = base_dir / "schema.sql"

def connectDB():
    conn = connect(db_path)
    cursor = conn.cursor()

    with open(schema_path, encoding="utf-8") as f:
            sqlcode = f.read()

    cursor.execute(sqlcode)

    return conn