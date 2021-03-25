import os
import requests
import logging
from flask import session
from flask_login import current_user

from util import b64encode_str
from constants import *


logger = logging.getLogger(FLASK_NAME)

def get_refreshed_access_token(refresh_token, vendor):
	""" Refreshes Access Token for given vendor """

	if vendor == BOSE_VENDOR_ID:
		bose_token_auth_header = 'Basic ' + b64encode_str(os.environ['BOSE_CLIENT_ID'] + ':' + os.environ['BOSE_SECRET'])
		bose_token_headers = {'Authorization': bose_token_auth_header}
		bose_token_data = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
		tokens = requests.post('https://partners.api.bose.io/auth/oauth/token', headers=bose_token_headers, data=bose_token_data)
		access_token = tokens.json().get('access_token', None)
		if access_token is None:
			logger.warning(f"Bose refresh token response did not provide access token: {tokens.json()}")
		return access_token

	elif vendor == SONOS_VENDOR_ID:
		sonos_token_auth_header = 'Basic ' + b64encode_str(os.environ['SONOS_CLIENT_ID'] + ':' + os.environ['SONOS_SECRET'])
		sonos_token_headers = {'Authorization': sonos_token_auth_header}
		sonos_token_data = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
		tokens = requests.post('https://api.sonos.com/login/v3/oauth/access', headers=sonos_token_headers, data=sonos_token_data)
		access_token = tokens.json().get('access_token', None)
		if access_token is None:
			logger.warning(f"Sonos refresh token response did not provide access token: {tokens.json()}")
		return access_token

	else:
		logger.warning(f"invalid vendor supplied - get_refreshed_access_token")
		return None


def get_products():
	""" Returns JSON Object with all Bose and/or Sonos products in BAM Schema 
	
	BAM Schema for Products:
	{
		'product_id': a machine-readable ID for the product
		'product_name': a human-readable name for the product - will be displayed in the UI
		'vendor': the vendor of the product
	}
	"""
	linked_vendors = {
		BOSE_VENDOR_ID: {
			'access': current_user.get_access_token(BOSE_VENDOR_ID),
			'refresh': current_user.get_refresh_token(BOSE_VENDOR_ID)
		},
		SONOS_VENDOR_ID: {
			'access': current_user.get_access_token(SONOS_VENDOR_ID),
			'refresh': current_user.get_refresh_token(SONOS_VENDOR_ID)
		}
	}

	available_products = []

	for vendor in linked_vendors:
		if vendor == BOSE_VENDOR_ID and linked_vendors[vendor]['refresh'] is not None:
			access_token = linked_vendors[vendor]['access']
			if access_token is None:
				access_token = 'nnn'
			bose_headers = {
				'Authorization': 'Bearer ' + access_token,
				'X-API-Version': os.environ['BOSE_API_VERSION'],
				'X-ApiKey': os.environ['BOSE_CLIENT_ID']
			}

			# Try to fetch Bose Products
			bose_products_res = requests.get('https://partners.api.bose.io/products', headers=bose_headers)
			logger.debug(bose_products_res.json())

			# If not successful, then access token probably expired, or some other issue
			if bose_products_res.status_code != 200:
				logger.error(f'Bose API Unsuccessful Response: {bose_products_res.status_code}')
				logger.error(f'Error Message: {bose_products_res.json()}')
				access_token = get_refreshed_access_token(linked_vendors[vendor]['refresh'], vendor)
				if access_token is None:
					current_user.clear_tokens(BOSE_VENDOR_ID)
				else:
					current_user.set_access_token(access_token, BOSE_VENDOR_ID)
					bose_headers.update({'Authorization': 'Bearer ' + access_token})
					bose_products_res = requests.get('https://partners.api.bose.io/products', headers=bose_headers)

			if 'results' in bose_products_res.json():
				bose_products_array = bose_products_res.json()['results']
				for p in bose_products_array:
					available_products.append({
						'product_id': p['productID'],
						'product_name': p['productName'],
						'vendor': BOSE_VENDOR_ID
					})			

		if vendor == SONOS_VENDOR_ID and linked_vendors[vendor]['refresh'] is not None:
			access_token = linked_vendors[vendor]['access']
			if access_token is None:
				access_token = 'nnn'
			sonos_headers = {
				'Authorization': 'Bearer ' + access_token
			}

			# Try to fetch Sonos Household
			# Eventual TODO - let a user pick their household. For now just take the first in the list
			sonos_household_res = requests.get('https://api.ws.sonos.com/control/api/v1/households', headers=sonos_headers)
			logger.debug(sonos_household_res.json())
			# If not successful, then access token probably expired, or some other issue
			if sonos_household_res.status_code != 200:
				logger.error(f'Sonos API Unsuccessful Response: {sonos_household_res.status_code}')
				logger.error(f'Error Message: {sonos_household_res.json()}')
				access_token = get_refreshed_access_token(linked_vendors[vendor]['refresh'], vendor)
				if access_token is None:
					current_user.clear_tokens(SONOS_VENDOR_ID)
				else:
					current_user.set_access_token(access_token, SONOS_VENDOR_ID)
					sonos_headers.update({'Authorization': 'Bearer ' + access_token})
					sonos_household_res = requests.get('https://api.ws.sonos.com/control/api/v1/households', headers=sonos_headers)
			
			sonos_household = sonos_household_res.json()['households'][0]['id']

			if sonos_household is not None: # if there's a Sonos Household
				sonos_products_res = requests.get(f'https://api.ws.sonos.com/control/api/v1/households/{sonos_household}/groups', headers=sonos_headers)
				if 'players' in sonos_products_res.json():
					sonos_products_array = sonos_products_res.json()['players']
					for p in sonos_products_array:
						sonos_product_capabilities = p['capabilities']
						if "AUDIO_CLIP" in sonos_product_capabilities:
							available_products.append({
								'product_id': p['id'],
								'product_name': p['name'],
								'vendor': SONOS_VENDOR_ID
							})

	return available_products

def send_audio_notification(access_token, refresh_token, vendor, product_id, msg_url, desired_volume=None):
	""" sends the specified URL as an Audio Notification to the specified product """
	if access_token is None:
		access_token = 'nnn'
	
	if vendor == BOSE_VENDOR_ID:
		bose_headers = {
			'Authorization': 'Bearer ' + access_token,
			'X-API-Version': os.environ['BOSE_API_VERSION'],
			'X-ApiKey': os.environ['BOSE_CLIENT_ID']
		}

		# Try to send AN
		bose_an_data = {
			'url': msg_url
		}

		if desired_volume is not None:
			bose_an_data.update({'volumeOverride': desired_volume})

		bose_an_res = requests.post(f'https://partners.api.bose.io/products/{product_id}/content/notify', headers=bose_headers, json=bose_an_data)

		# If not successful, then access token probably expired, or some other issue
		if bose_an_res.status_code != 202:
			logger.error(f'Bose API Unsuccessful Response: {bose_an_res.status_code}')
			logger.error(f'Error Message: {bose_an_res.json()}')
			access_token = get_refreshed_access_token(refresh_token, vendor)
			if access_token is None:
				current_user.clear_tokens(BOSE_VENDOR_ID)
			else:
				current_user.set_access_token(access_token, BOSE_VENDOR_ID)
				bose_headers.update({'Authorization': 'Bearer ' + access_token})
				bose_an_res = requests.post(f'https://partners.api.bose.io/products/{product_id}/content/notify', headers=bose_headers, json=bose_an_data)	

		return bose_an_res	

	elif vendor == SONOS_VENDOR_ID:
		sonos_headers = {
			'Authorization': 'Bearer ' + access_token
		}

		# Try to send AN
		sonos_an_data = {
			'name': 'Brief Audio Message',
			'appId': 'com.bam-demo',
			'streamUrl': msg_url,
		}

		if desired_volume is not None:
			sonos_an_data.update({'volume': desired_volume})

		sonos_an_res = requests.post(f'https://api.ws.sonos.com/control/api/v1/players/{product_id}/audioClip', headers=sonos_headers, json=sonos_an_data)

		# If not successful, then access token probably expired, or some other issue
		if sonos_an_res.status_code != 200:
			logger.error(f'Sonos API Unsuccessful Response: {sonos_an_res.status_code}')
			logger.error(f'Error Message: {sonos_an_res.json()}')
			access_token = get_refreshed_access_token(refresh_token, vendor)
			if access_token is None:
				current_user.clear_tokens(SONOS_VENDOR_ID)
				return None
			else:
				current_user.set_access_token(access_token, SONOS_VENDOR_ID)
				sonos_headers.update({'Authorization': 'Bearer ' + access_token})
				sonos_an_res = requests.post(f'https://api.ws.sonos.com/control/api/v1/players/{product_id}/audioClip', headers=sonos_headers, json=sonos_an_data)

		return sonos_an_res	
	
	else:
		return None
	