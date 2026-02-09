from os import urandom
from hashlib import sha256

def createSalt():
    salt = urandom(16)
    return salt

#Create a hash in hexadecimal
def hashing(password:str ,salt:bytes):
    password_hash = sha256(salt + password.encode('utf-8')).hexdigest()
    return password_hash