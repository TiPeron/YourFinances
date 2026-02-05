CREATE TABLE IF NOT EXISTS user_login (
    id_user  INTEGER PRIMARY KEY,
    password CHAR(64) NOT NULL,
    salt     CHAR(32) NOT NULL,
    name     TEXT NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    CNPJ     TEXT UNIQUE,
    CPF      TEXT UNIQUE,
    phone    TEXT UNIQUE
);