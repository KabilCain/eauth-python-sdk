import win32security
import requests
import json
import platform
import hashlib
import os
import webbrowser
import sys
import string
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Required configuration
application_token = "application_token_here" # Your application token goes here
application_secret = "application_secret_here" # Your application secret goes here
application_version = "application_version_here" # Your application version goes here

# Advanced configuration
invalid_request_message = "Invalid request!"
outdated_version_message = "Outdated version, please upgrade!"
busy_sessions_message = "Please try again later!"
unavailable_session_message = "Invalid session. Please re-launch the app!"
used_session_message = "Why did the computer go to therapy? Because it had a case of 'Request Repeatitis' and couldn't stop asking for the same thing over and over again!"
overcrowded_session_message = "Session limit exceeded. Please re-launch the app!"
expired_session_message = "Your session has timed out. Please re-launch the app!"
invalid_user_message = "Incorrect login credentials!"
banned_user_message = "Access denied!"
incorrect_hwid_message = "Hardware ID mismatch. Please try again with the correct device!"
expired_user_message = "Your subscription has ended. Please renew to continue using our service!"
used_name_message = "Username already taken. Please choose a different username!"
invalid_key_message = "Invalid key. Please enter a valid key!"
upgrade_your_eauth_message = "Upgrade your Eauth plan to exceed the limits!"
cooldown_hwid_message = "You have not yet reached your reset cool down, please try again later."
invalid_user_hwid_message = "The user either has a null HWID or is unavailable."

# Dynamic configuration
init = False
login = False
register = False

session_id = ""
error_message = ""

rank = ""
register_date = ""
expire_date = ""
hwid = ""
user_hwid = ""

def compute_sha512(input_string):
    sha512 = hashlib.sha512()
    sha512.update(input_string.encode('utf-8'))
    return sha512.hexdigest()

def generate_Eauth_header(message, app_secret):
    auth_token = app_secret + message
    return compute_sha512(auth_token)

characters = string.ascii_uppercase + string.ascii_lowercase + string.digits

def generate_random_string(length=18):
    return ''.join(random.choices(characters, k=length))
    
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn2rh1JxHmjlu2UhR80g1
issihSD2Xuf5Pevlu0ZfRqFkgfdSxCyDwguNo9oTSG+wArktK7QJ0Xao+dsgg1vB
c7/mF/S+cdiCl8Gg8RTDvHZObqnoPQy8KgaqzilT5KMLp/1r5meky1bRmhFn3F17
Zkt3VQvM6T+99AMA6l/nDc0U8Xc1UvX9WrnR4UoBYWtO19/UaP/Z0zsFiSlu9iXP
QotGlL14gQvyByXE2icMR198/dj+wLV9Kirb17KuJtxQo9IHbVAPX3YZ72NPkDR0
hlATbgwXoLsvy1Jp3LLSV/kUWkWgQgcHp2WXNycpgVJDmfmna+mq0nhDSdCRoBl9
slU1xvBZTya/IAt5SqfazM/b0xM/uleXISx+oHjRIRM8Se26OByUl6Rtjkg/uSxj
Jk5ljAR0WjmC4fHD7fLEVbKG8SdQxHN5fb565hh8LlwG1ER6SaxmpmK2N5JC+FLQ
ihCJVDllLU5AwppZbv4PKUMprjNxZO41cKCcNUBxTX442k8HcXDqoRM2icjb4X35
SGie3lIw+WvEOr5Hr0vhoQnAwree2BnqMVZIjH34L5vObeToeTnUwXKJ9o7fGRhI
9P00gyzsFHQgiMKOygioj9NdobtPIPahcStagR9PQLR117Fhyx2R9RSZESZB4pIY
FtlOd7spqVctsJWnfVo9ai0CAwEAAQ==
-----END PUBLIC KEY-----"""

public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())

# Send post request to Eauth
def run_request(request_data):
    signature = generate_Eauth_header(request_data, application_secret)
    response = requests.post('https://eauth.us.to/api/1.3/',
                             headers={"Content-Type": "application/json", "User-Agent": signature},
                             data=request_data, verify=True)
    
    res = json.loads(response.text)
    message = res['message']

    # Read signature
    if (message != 'invalid_request' and message != 'session_unavailable' and message != 'session_already_used' and message != 'invalid_email'):
        Eauth_header = base64.b64decode(response.headers.get('Signature'))
        try:
            public_key.verify(Eauth_header, generate_Eauth_header(message + response.text, application_secret).encode('utf-8'), padding.PKCS1v15(),hashes.SHA256())
        except:
            sys.exit(1)

        if (res['pair'] != signature):
            sys.exit(1)
   
    return response.text

def raise_error(error):
    global error_message
    error_message = error

# Eauth init request
def init_request():
    # Establish HWID

    global user_hwid

    if platform.system() == 'Windows':
        user_hwid = win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, os.getlogin())[0])
    elif platform.system() == "Linux":
        with open("/etc/machine-id") as f:
            user_hwid = f.read()
    
    # Acutal init request

    global init, session_id, app_status, app_name, logged_message, registered_message, error_message

    if (init):
        return init
    
    data = {
        'type': 'init',
        'token': application_token,
        'hwid': user_hwid,
        'version': application_version,
        'pair': generate_random_string()
    }

    json_string = run_request(json.dumps(data))
    data = json.loads(json_string)
    message = data['message']

    # Check response
    if (message == 'init_success'):
        init = True
        session_id = data['session_id']
    elif (message == 'invalid_request'):
        raise_error(invalid_request_message)
    elif (message == 'version_outdated'):
        download_link = data['download_link']
        if (download_link != ''):
            webbrowser.open(download_link)
        raise_error(outdated_version_message)
    elif (message == 'maximum_sessions_reached'):
        raise_error(busy_sessions_message)
    elif (message == 'user_is_banned'):
        raise_error(banned_user_message)
    elif (message == 'init_paused'):
        raise_error(data['paused_message'])

    # Return
    return init

# Eauth login request
def login_request(username, password):
    global login, rank, register_date, expire_date, hwid, error_message

    if (login):
        return login
    
    data = {
        'type': 'login',
        'session_id': session_id,
        'username': username,
        'password': password,
        'hwid': user_hwid,
        'pair': generate_random_string()
    }

    json_string = run_request(json.dumps(data))
    data = json.loads(json_string)
    message = data['message']

    # Check response
    if (message == 'login_success'):
        login = True
        rank = data['rank']
        register_date = data['register_date']
        expire_date = data['expire_date']
        hwid = data['hwid']
    elif (message == 'invalid_request'):
        raise_error(invalid_request_message)
    elif (message == 'session_unavailable'):
        raise_error(unavailable_session_message)
    elif (message == 'session_already_used'):
        raise_error(used_session_message)
    elif (message == 'session_overcrowded'):
        raise_error(overcrowded_session_message)
    elif (message == 'session_expired'):
        raise_error(expired_session_message)
    elif (message == 'account_unavailable'):
        raise_error(invalid_user_message)
    elif (message == 'user_is_banned'):
        raise_error(banned_user_message)
    elif (message == 'hwid_incorrect'):
        raise_error(incorrect_hwid_message)
    elif (message == 'subscription_expired'):
        raise_error(expired_session_message)

    return login

# Eauth register request
def register_request(username, password, key):
    global register, error_message

    if (register):
        return register
    
    data = {
        'type': 'register',
        'session_id': session_id,
        'username': username,
        'password': password,
        'key': key,
        'hwid': user_hwid,
        'pair': generate_random_string()
    }

    json_string = run_request(json.dumps(data))
    data = json.loads(json_string)
    message = data['message']

    # Check response
    if (message == 'register_success'):
        register = True
    elif (message == 'invalid_request'):
        raise_error(invalid_request_message)
    elif (message == 'session_unavailable'):
        raise_error(unavailable_session_message)
    elif (message == 'session_already_used'):
        raise_error(used_session_message)
    elif (message == 'session_overcrowded'):
        raise_error(overcrowded_session_message)
    elif (message == 'session_expired'):
        raise_error(expired_session_message)
    elif (message == 'account_unavailable'):
        raise_error(invalid_user_message)
    elif (message == 'name_already_used'):
        raise_error(used_name_message)
    elif (message == 'key_unavailable'):
        raise_error(invalid_key_message)
    elif (message == 'user_is_banned'):
        raise_error(banned_user_message)
    elif (message == 'maximum_users_reached'):
        raise_error(upgrade_your_eauth_message)

    return register
    
# Eauth reset HWID request
def hardware_reset_request(username):
    data = {
        'type': 'hardware_reset',
        'session_id': session_id,
        'username': username,
        'pair': generate_random_string()
    }

    json_string = run_request(json.dumps(data))
    data = json.loads(json_string)
    message = data['message']

    # Check response
    if (message == 'reset_success'):
        return True
    elif (message == 'invalid_request'):
        raise_error(invalid_request_message)
    elif (message == 'session_unavailable'):
        raise_error(unavailable_session_message)
    elif (message == 'session_expired'):
        raise_error(expired_session_message)
    elif (message == 'invalid_user'):
        raise_error(invalid_user_hwid_message)
    elif (message == 'cooldown_not_reached'):
        response = cooldown_hwid_message + " @ " + data['estimated_reset_time']
        raise_error(response)

    return False

# Check the session
def auth_monitor():
    data = {
        'type': 'auth_monitor',
        'session_id': session_id,
        'pair': generate_random_string()
    }

    json_string = run_request(json.dumps(data))
    data = json.loads(json_string)
    message = data['message']

    # Check response
    if (message == 'up'):
        return True

    return False

# Check the user
def user_monitor(username):
    data = {
        'type': 'auth_monitor',
        'session_id': session_id,
        'username': username,
        'pair': generate_random_string()
    }

    json_string = run_request(json.dumps(data))
    data = json.loads(json_string)
    message = data['message']

    # Check response
    if (message == 'up'):
        return True

    return False
