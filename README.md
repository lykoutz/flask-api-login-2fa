# Flask Registration and Login with 2FA API

### Requirements
Minimal Docker requirements should be installed: 
``` 
Docker engine:   20.10.21
Docker compose:  1.25.3
```

### Run app locally with docker compose
Clone the repository and then into the project folder run the build and wait it to finish.
    
    docker-compose up -d --build --force-recreate

You should see two running containers, one for the flask application and the other one for the postgres where data are stored.
From now on, the APIs defined below are ready to be used.

To run the tests, please first login to the new container:
    
    docker exec -it flask.registration_login_api bash

and launch the command:

    pytest -v tests.py --setup-show

# API Endpoints

| Title | Method | Endpoints | Action |
| :--- | :--- | :--- | :--- |
| [Registration](#registration) | POST | /signup | To sign up a new user account |
| [Login](#login) | POST | /login | To login an existing user account |
| [Login 2FA](#login-2fa) | POST | /login-2fa-validation | To validate 2FA |
| [Logout](#logout) | GET | /logout | To logout an user |

### Registration

### Request

`POST /signup`

| Attribute     | Type     | Required | Description           |
|:--------------|:---------|:---------|:----------------------|
| `email`       | string   | Yes      | User email. |
| `password`    | string   | Yes      | User password. |
| `first_name`  | string   | No       | User first name. |
| `last_name`   | string   | No       | User last name. |
| `otp_enabled` | boolean  | No       | Default value is `False` which means no 2FA enable. `True` to enable 2FA. |


Example:

    curl -i -X POST -H "Content-Type: application/json" -d '{"email": "mario.rossi@test.com", "password": "test1234", "first_name": "mario", "last_name": "rossi", "otp_enabled": true}' localhost:5000/signup

### Response

| Status code | Response | Description           |
|:--------------|:---------|:----------------------|
| 201         | {"message": "*user* registered successfully"} | User registered successfully. |
| 400         | {"error": {...}} | When fields are wrong or missing. |
| 409         | {"error": "Account already exists"} | Email already stored. |


## Login

### Request

`POST /login`

| Attribute     | Type     | Required | Description           |
|:--------------|:---------|:---------|:----------------------|
| `email`       | string   | Yes      | User email. |
| `password`    | string   | Yes      | User password. |


Example:

    curl -i -c /tmp/cookie -X POST -H "Content-Type: application/json" -d '{"email": "mario.rossi@test.com", "password": "test1234"}' localhost:5000/login

### Response

| Status code | Response | Description           |
|:--------------|:---------|:----------------------|
| 200         | {"message": "*user* logged in successfully"} | User with 2Fa disabled logged in successfully. |
| 200         | {"otp": "valid otp"} | User with 2FA enabled logged in successfully. *NB: Do not send OTP code in response in production environment.*|
| 400         | {"error": {...}} | When email or password is missing. |
| 401         | {"error": "Invalid credentials"} | When email or password is incorrect. |


## Login 2FA

### Request

`POST /login-2fa-validation`

| Attribute     | Type     | Required | Description           |
|:--------------|:---------|:---------|:----------------------|
| `otp`       | string   | Yes      | OTP code to validate 2FA Authentication. |


Example:

    curl -i -b /tmp/cookie -c /tmp/cookie -X POST -H "Content-Type: application/json" -d '{"otp":"IBPQTUE6DYZE7QLKHVTV6LMEMHGGKF4P"}' localhost:5000/login-2fa-validation

### Response

| Status code | Response | Description           |
|:--------------|:---------|:----------------------|
| 200         | {"otp_valid": true} | 2FA Authentication completed successfully. |
| 400         | {"error": {...} | When otp is missing or is not valid. |
| 401         | {"error": "Token expired. Please log in again."} | When 2FA validity period (set to 30 secs) is expired. |
| 409         | {"error": "User 2FA is disabled."} | When trying to authenticate 2FA for user who did not enabled it in registration. |


## Logout

### Request

`GET /logout`

Example:

    curl -b /tmp/cookie -c /tmp/cookie localhost:5000/logout -i

### Response

| Status code | Response | Description           |
|:--------------|:---------|:----------------------|
| 200         | {"message": "Logged out successfully"} | User logged out successfully. |
| 401         | {"error": "Invalid token. Please log in again."} | When trying to call without logged in. |
# flask-api-login-2fa
