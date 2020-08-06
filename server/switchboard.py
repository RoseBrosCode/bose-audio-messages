import os
import requests
import logging
from flask import session

from util import b64encode_str
from constants import *


logger = logging.getLogger(FLASK_NAME)

def refresh_sb_token(refresh_token):
	""" Refreshes Switchboard Access Token """
	t_auth_header = 'Basic ' + b64encode_str(os.environ['SB_CLIENT_ID'] + ':' + os.environ['SB_SECRET'])
	t_headers = {'Authorization': t_auth_header}
	t_data = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
	tokens = requests.post('https://partners.api.bose.io/auth/oauth/token', headers=t_headers, data=t_data)
	access_token = tokens.json().get('access_token', None)
	if access_token is None:
		logger.warning(f"refresh token response did not provide access token: {tokens.json()}")
	return access_token


def get_products(acc_token):
	""" Returns JSON Object Switchboard GET /products response """
	sb_headers = {
		'Authorization': 'Bearer ' + acc_token,
		'X-API-Version': os.environ['SB_API_VERSION'],
		'X-ApiKey': os.environ['SB_CLIENT_ID']
	}

	products_res = requests.get('https://partners.api.bose.io/products', headers=sb_headers)

	return products_res

def send_audio_notification(acc_token, product_id, msg_url, volume=None):
	""" sends the specified URL as an Audio Notification to the specified product """
	sb_headers = {
		'Authorization': 'Bearer ' + acc_token,
		'X-API-Version': os.environ['SB_API_VERSION'],
		'X-ApiKey': os.environ['SB_CLIENT_ID']
	}

	sb_an_data = {
		'url': msg_url
	}

	if volume is not None:
		sb_an_data.update(volumeOverride=volume)

	logger.debug(sb_an_data)
	an_res = requests.post(f'https://partners.api.bose.io/products/{product_id}/content/notify', headers=sb_headers, json=sb_an_data)

	return an_res
	