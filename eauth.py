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

# Send post request to Eauth
def run_request(request_data):
    response = requests.post('https://eauth.us.to/api/1.2/',
                             headers={"Content-Type": "application/json", "User-Agent": generate_Eauth_header(request_data, application_secret)},
                             data=request_data)
    
    res = json.loads(response.text)
    message = res['message']

    # Read signature
    Eauth_header = response.headers.get('Eauth')
    if (message != 'invalid_request' and message != 'session_unavailable' and message != 'session_already_used' and message != 'invalid_email'):
        if (Eauth_header != generate_Eauth_header(response.text, application_secret)):
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
        raise_error(cooldown_hwid_message)

    return False