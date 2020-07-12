import os
import requests
from flask import session

from util import b64encode_str


def refresh_sb_token():
    """ Refreshes Switchboard Access Token """
    if session['refresh_token'] is None:
        return None
    else:
        t_auth_header = 'Basic ' + b64encode_str(os.environ['SB_CLIENT_ID'] + ':' + os.environ['SB_SECRET'])
        t_headers = {'Authorization':t_auth_header}
        t_data = {'grant_type':'refresh_token', 'refresh_token': session['refresh_token']}
        tokens = requests.post('https://partners.api.bose.io/auth/oauth/token', headers=t_headers, data=t_data)
        return tokens.json()['access_token']


def get_products(acc_token):
    """ Returns JSON Object Switchboard GET /products response """
    sb_headers = {
        'Authorization': 'Bearer ' + acc_token,
        'X-API-Version': os.environ['SB_API_VERSION'],
        'X-ApiKey': os.environ['SB_CLIENT_ID']
    }

    products_res = requests.get('https://partners.api.bose.io/products', headers=sb_headers)

    return products_res