import os
import streamlit as st
from dotenv import load_dotenv
import requests
import base64
import json

load_dotenv()
COGNITO_DOMAIN = os.environ.get("COGNITO_DOMAIN")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
APP_URI = os.environ.get("APP_URI")


def init_state():
    if "auth_code" not in st.session_state:
        st.session_state["auth_code"] = ""
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "user_cognito_groups" not in st.session_state:
        st.session_state["user_cognito_groups"] = []

# Get the authorization code after the user has logged in
def get_auth_code():
    auth_query_params = st.experimental_get_query_params()
    try:
        auth_code = dict(auth_query_params)["code"][0]
    except (KeyError, TypeError):
        auth_code = ""
    return auth_code


# Set the authorization code after the user has logged in
def set_auth_code():
    init_state()
    auth_code = get_auth_code()
    st.session_state["auth_code"] = auth_code


# Get the access token from the authorization code
def get_user_tokens(auth_code):
    # Variables to make a post request
    token_url = f"{COGNITO_DOMAIN}/oauth2/token"
    client_secret_string = f"{CLIENT_ID}:{CLIENT_SECRET}"
    client_secret_encoded = str(
        base64.b64encode(client_secret_string.encode("utf-8")), "utf-8"
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {client_secret_encoded}",
    }
    body = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": auth_code,
        "redirect_uri": APP_URI,
    }

    token_response = requests.post(token_url, headers=headers, data=body)
    try:
        access_token = token_response.json()["access_token"]
        id_token = token_response.json()["id_token"]
    except (KeyError, TypeError):
        access_token = ""
        id_token = ""

    return access_token, id_token


# Use access token to retrieve user info
def get_user_info(access_token):
    userinfo_url = f"{COGNITO_DOMAIN}/oauth2/userInfo"
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Authorization": f"Bearer {access_token}",
    }

    userinfo_response = requests.get(userinfo_url, headers=headers)

    return userinfo_response.json()


# Decode access token to JWT to get user's cognito groups
def pad_base64(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += "=" * (4 - missing_padding)
    return data


def get_user_cognito_groups(id_token):
    user_cognito_groups = []
    if id_token != "":
        header, payload, signature = id_token.split(".")
        printable_payload = base64.urlsafe_b64decode(pad_base64(payload))
        payload_dict = json.loads(printable_payload)
        try:
            user_cognito_groups = list(dict(payload_dict)["cognito:groups"])
        except (KeyError, TypeError):
            pass
    return user_cognito_groups


# Set streamlit state variables
def set_st_state_vars():
    init_state()
    auth_code = get_auth_code()
    access_token, id_token = get_user_tokens(auth_code)
    user_cognito_groups = get_user_cognito_groups(id_token)

    if access_token != "":
        st.session_state["auth_code"] = auth_code
        st.session_state["authenticated"] = True
        st.session_state["user_cognito_groups"] = user_cognito_groups


# Login/ Logout HTML components
login_link = f"{COGNITO_DOMAIN}/login?client_id={CLIENT_ID}&response_type=code&scope=email+openid&redirect_uri={APP_URI}"
logout_link = f"{COGNITO_DOMAIN}/logout?client_id={CLIENT_ID}&logout_uri={APP_URI}"

html_css_login = """
<style>
.button-login {
  background-color: skyblue;
  color: white !important;
  padding: 1em 1.5em;
  text-decoration: none;
  text-transform: uppercase;
}

.button-login:hover {
  background-color: #555;
  text-decoration: none;
}

.button-login:active {
  background-color: black;
}

</style>
"""

html_button_login = (
    html_css_login
    + f"<a href='{login_link}' class='button-login' target='_self'>Log In</a>"
)
html_button_logout = (
    html_css_login
    + f"<a href='{logout_link}' class='button-login' target='_self'>Log Out</a>"
)


def button_login():
    return st.sidebar.markdown(f"{html_button_login}", unsafe_allow_html=True)


def button_logout():
    return st.sidebar.markdown(f"{html_button_logout}", unsafe_allow_html=True)
