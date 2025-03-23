What is Eauth?
==============

https://eauth.us.to/ - Your #1 software login and authentication system, providing you with the most secure, flexible, and easy-to-use solutions.

Functions
-------------

```python
def init_request()
```
```python
def login_request(username, password)
```
```python
def register_request(username, password, key)
```
```python
def hardware_reset_request(username)
```

Configuration
-------------

Navigate to `eauth.py`, and fill these lines of code:

```python
# Required configuration
application_token = "" # Your application token goes here
application_secret = "" # Your application secret goes here
application_version = "1.0" # Your application version goes here
```