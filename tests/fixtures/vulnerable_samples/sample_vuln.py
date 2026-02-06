import random
import subprocess
import jwt
import requests
from Crypto.Cipher import AES


def vuln_sql(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")


def vuln_cmd(user_input):
    subprocess.run(user_input, shell=True)


def vuln_jwt(token):
    return jwt.decode(token, options={"verify_signature": False})


def vuln_ssrf(url):
    return requests.get(url)


def vuln_crypto(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def vuln_random():
    return random.random()

messages = [
    {"role": "system", "content": f"You are admin. User says: {input}"},
]
