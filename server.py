import base64
import hmac
import hashlib
import json

from typing import Optional

from fastapi import FastAPI, Form, Cookie, encoders, Body
from fastapi import responses
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "d0bf2c756249a853bec9dc6c8787505e8cdd3546dd78dac7d86e0a50003f0efb"
PASSWORD_SALT = "a1afcc28444653f6b6d96e341dc5092d5a1bc54fc8e1b83d49e32b60b4b89925"

def sing_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod = hashlib.sha256
        ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sing = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sing_data(username)
    if hmac.compare_digest(valid_sign, sing):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return  password_hash == stored_password_hash        

users = {
    "alexey@user.com": {
        "name": "Алексей",
        "password": "257d3564c8994d583b4e66e81948ba470ada96527e67aa1a5d8843f591a7e674",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Пётр",
        "password": "d533d537cfce59e75576256091e3ea82203f083efa4f686776fadc1c4983b467",
        "balance": 555_555
    }
}

@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}",
        media_type='text/html')
    
@app.post('/login')
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": 'Я вас не знаю!'
            }),
            media_type='application/json')
    responce = Response(
            json.dumps({
                "success": True,
                "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
            }),
        media_type='application/json')
    username_singed = base64.b64encode(username.encode()).decode() + "." + sing_data(username)
    responce.set_cookie(key='username', value=username_singed)    
    return responce