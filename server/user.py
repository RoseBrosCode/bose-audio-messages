import os
import requests
import redis
import logging
import uuid

from flask import flash
from flask_login import UserMixin, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from redis.exceptions import LockError
from cryptography.fernet import Fernet, InvalidToken
from google.oauth2 import id_token
from google.auth.transport import requests as g_requests

from constants import *


logger = logging.getLogger(FLASK_NAME)

# Initialize Redis connection
db = redis.Redis.from_url(os.environ.get("REDIS_URL"))

# Test Redis connection
if not db.ping():
	logger.error("unable to ping redis")
else:
	logger.debug(f"connected to redis at {os.environ.get('REDIS_URL')}")

# Load Redis encryption key
encryption_key = os.environ["REDIS_ENCRYPTION_KEY"]
try:
	secret_key = Fernet(encryption_key)
	logger.debug("loaded encryption key")
except Exception as e:
	logger.error(f"failed to load encryption key: {e}")
	raise

class User(UserMixin):
	"""Models a user of BAM."""

	def __init__(self, user_id, username, password_hash, encrypted_provider_access_token, acct_type=BAM_ACCT_TYPE, encrypted_refresh_token=None, encrypted_access_token=None, bose_encrypted_refresh_token=None, bose_encrypted_access_token=None, sonos_encrypted_refresh_token=None, sonos_encrypted_access_token=None, preferred_volume=DEFAULT_PREFERRED_VOLUME):
		self.user_id = user_id
		self.username = username
		self.password_hash = password_hash
		self.encrypted_provider_access_token = encrypted_provider_access_token
		self.acct_type = acct_type
		self.encrypted_refresh_token = encrypted_refresh_token # deprecated, kept for backwards compatibility
		self.encrypted_access_token = encrypted_access_token # deprecated, kept for backwards compatibility
		self.bose_encrypted_refresh_token = bose_encrypted_refresh_token
		self.bose_encrypted_access_token = bose_encrypted_access_token
		self.sonos_encrypted_refresh_token = sonos_encrypted_refresh_token
		self.sonos_encrypted_access_token = sonos_encrypted_access_token
		self.preferred_volume = preferred_volume

	@staticmethod
	def load_user(user_id, retries=1):
		"""Loads a user from Redis."""
		try:
			user_dict = db.hgetall(f"user:{user_id}")
		except ConnectionError:
			logger.warning(f"unable to load_user, retries remaining = {retries}")
			if retries > 0:
				return User.load_user(user_id, retries=retries-1)
			return None
		except Exception as e:
			logger.error(f"unable to load_user, unhandled exception: {e}")
			return None
		if user_dict:
			return User.from_dict(user_dict)
		return None

	@staticmethod
	def from_dict(d):
		"""Populates a User object from a dict returned from Redis."""
		# Ensure all keys and values are strings
		d = { key.decode() if type(key) == bytes 
				else key:
			  val.decode() if type(val) == bytes 
				else val 
				for key, val in d.items() }
		logger.debug(f"getting user from dict: {d}")
		return User(d.get("user_id", None), d.get("username", None), d.get("password_hash", None), d.get("encrypted_provider_access_token", None),
					d.get("acct_type", None), d.get("encrypted_refresh_token", None), d.get("encrypted_access_token", None), 
					d.get("bose_encrypted_refresh_token", None), d.get("bose_encrypted_access_token", None),d.get("sonos_encrypted_refresh_token", None), d.get("sonos_encrypted_access_token", None), d.get("preferred_volume", None))

	@staticmethod
	def get_user_by_username(username, retries=1):
		"""Looks up a user by username."""
		try:
			username_lower = username.lower()
			user_id = db.hget(f"users:", username_lower)
			if user_id:
				return User.load_user(user_id.decode())
		except ConnectionError:
			logger.warning(f"unable to get_user_by_username, retries remaining = {retries}")
			if retries > 0:
				return User.get_user_by_username(username, retries=retries-1)
			return None
		return None

	@staticmethod
	def create_user(username, password=None, provider_access_token=None, acct_type=BAM_ACCT_TYPE, retries=1):
		"""Creates a new user and stores it in Redis."""
		# Case insensitive usernames
		username_lower = username.lower()

		try:
			with db.lock("user_lock", blocking_timeout=1):
				# Ensure username is unique
				if db.hget("users:", username_lower):
					logger.warning(f"username {username_lower} already exists")
					return None

				# Create transaction
				pipeline = db.pipeline()

				# Claim username
				user_id = str(uuid.uuid4())
				pipeline.hset("users:", username_lower, user_id)

				# Create user entry
				# If password exists, hash it
				password_hash = ""
				if password:
					password_hash = generate_password_hash(password)

				# If provider_access_token exists, encrypt it
				encrypted_provider_access_token = ""
				if provider_access_token:
					encrypted_provider_access_token = secret_key.encrypt(provider_access_token.encode())

				user_dict = {
					"user_id": user_id,
					"username": username_lower,
					"password_hash": password_hash,
					"encrypted_provider_access_token": encrypted_provider_access_token,
					"acct_type": acct_type,
					"preferred_volume": DEFAULT_PREFERRED_VOLUME
				}
				pipeline.hset(f"user:{user_id}", mapping=user_dict)

				# Execute transaction
				pipeline.execute()

				# Return user
				return User.from_dict(user_dict)
		except (LockError, ConnectionError):
			logger.error(f"unable to create_user, retries remaining = {retries}")
			if retries > 0:
				return User.create_user(username, password, retries=retries-1)
			return None
		except Exception as e:
			logger.error(f"unable to create_user, unhandled exception: {e}")
			return None

	@staticmethod
	def username_exists(username, retries=1):
		# Case insensitive usernames
		username_lower = username.lower()

		with db.lock("user_lock", blocking_timeout=1):
			try:
				return db.hget("users:", username_lower)
			except (LockError, ConnectionError):
				logger.error(f"unable to check username_exists, retries remaining = {retries}")
				if retries > 0:
					return User.username_exists(username, retries=retries-1)
				return None
			except Exception as e:
				logger.error(f"unable to check username_exists, unhandled exception: {e}")
				return None   

	def check_password(self, password):
		"""Validates an input password."""
		return check_password_hash(self.password_hash, password)

	def get_id(self):
		return self.user_id

	def get_refresh_token(self, vendor, retries=1):
		if vendor == BOSE_VENDOR_ID:
			# if legacy token is present, copy over to bose_encrypted_refresh_token locally and in db, and then delete
			if self.encrypted_refresh_token: 
				self.bose_encrypted_refresh_token = self.encrypted_refresh_token
				# set new token in db
				try:
					db.hset(f"user:{self.user_id}", "bose_encrypted_refresh_token", self.bose_encrypted_refresh_token)
				except ConnectionError:
					logger.error(f"unable to set new bose_encrypted_refresh_token in db, retries remaining = {retries}")
					if retries > 0:
						return self.get_refresh_token(vendor, retries=retries-1)
					return None
				retries = 1
				# clear legacy token from db and current user
				try:
					# Create transaction
					pipeline = db.pipeline()

					# Delete legacy refresh token
					pipeline.hdel(f"user:{self.user_id}", "encrypted_refresh_token")
					self.encrypted_refresh_token = None

					# Delete legacy access token
					pipeline.hdel(f"user:{self.user_id}", "encrypted_access_token")
					self.encrypted_access_token = None

					# Execute transaction
					pipeline.execute()
				except ConnectionError:
					logger.error(f"unable to clear legacy tokens from db, retries remaining = {retries}")
					if retries > 0:
						return self.get_refresh_token(vendor, retries=retries-1)
			
			if self.bose_encrypted_refresh_token:
				return secret_key.decrypt(self.bose_encrypted_refresh_token.encode()).decode()
			return None
		
		elif vendor == SONOS_VENDOR_ID:
			if self.sonos_encrypted_refresh_token:
				return secret_key.decrypt(self.sonos_encrypted_refresh_token.encode()).decode()
			return None
		
		return None

	def set_refresh_token(self, refresh_token, vendor, retries=1):
		try:
			if vendor == BOSE_VENDOR_ID:
				self.bose_encrypted_refresh_token = secret_key.encrypt(refresh_token.encode())
				db.hset(f"user:{self.user_id}", "bose_encrypted_refresh_token", self.bose_encrypted_refresh_token)
			
			elif vendor == SONOS_VENDOR_ID:
				self.sonos_encrypted_refresh_token = secret_key.encrypt(refresh_token.encode())
				db.hset(f"user:{self.user_id}", "sonos_encrypted_refresh_token", self.sonos_encrypted_refresh_token)

			else:
				return False

		except ConnectionError:
			logger.error(f"unable to set {vendor} refresh token, retries remaining = {retries}")
			if retries > 0:
				return self.set_refresh_token(refresh_token, vendor, retries=retries-1)
			return False

		return True

	def get_access_token(self, vendor, retries=1):
		if vendor == BOSE_VENDOR_ID:
			# if legacy token is present, copy over to bose_encrypted_access_token locally and in db, and then delete
			if self.encrypted_access_token: 
				self.bose_encrypted_access_token = self.encrypted_access_token
				# set new token in db
				try:
					db.hset(f"user:{self.user_id}", "bose_encrypted_access_token", self.bose_encrypted_access_token)
				except ConnectionError:
					logger.error(f"unable to set new bose_encrypted_access_token in db, retries remaining = {retries}")
					if retries > 0:
						return self.get_access_token(vendor, retries=retries-1)
					return None
				retries = 1
				# clear legacy token from db and current user
				try:
					# Create transaction
					pipeline = db.pipeline()

					# Delete legacy refresh token
					pipeline.hdel(f"user:{self.user_id}", "encrypted_refresh_token")
					self.encrypted_refresh_token = None

					# Delete legacy access token
					pipeline.hdel(f"user:{self.user_id}", "encrypted_access_token")
					self.encrypted_access_token = None

					# Execute transaction
					pipeline.execute()
				except ConnectionError:
					logger.error(f"unable to clear legacy tokens from db, retries remaining = {retries}")
					if retries > 0:
						return self.get_access_token(vendor, retries=retries-1)
					# if this fails repeatedly, it's ok to leave them for now
			
			if self.bose_encrypted_access_token:
				return secret_key.decrypt(self.bose_encrypted_access_token.encode()).decode()
			return None
		
		elif vendor == SONOS_VENDOR_ID:
			if self.sonos_encrypted_access_token:
				return secret_key.decrypt(self.sonos_encrypted_access_token.encode()).decode()
			return None
		
		return None

	def set_access_token(self, access_token, vendor, retries=1):
		try:
			if vendor == BOSE_VENDOR_ID:
				self.bose_encrypted_access_token = secret_key.encrypt(access_token.encode())
				db.hset(f"user:{self.user_id}", "bose_encrypted_access_token", self.bose_encrypted_access_token)
			
			elif vendor == SONOS_VENDOR_ID:
				self.sonos_encrypted_access_token = secret_key.encrypt(access_token.encode())
				db.hset(f"user:{self.user_id}", "sonos_encrypted_access_token", self.sonos_encrypted_access_token)

			else:
				return False

		except ConnectionError:
			logger.error(f"unable to set {vendor} access token, retries remaining = {retries}")
			if retries > 0:
				return self.set_access_token(access_token, vendor, retries=retries-1)
			return False
		return True

	def get_provider_access_token(self):
		if self.encrypted_provider_access_token:
			return secret_key.decrypt(self.encrypted_provider_access_token.encode()).decode()
		return None

	def set_provider_access_token(self, provider_access_token, retries=1):
		self.encrypted_provider_access_token = secret_key.encrypt(provider_access_token.encode())
		try:
			db.hset(f"user:{self.user_id}", "encrypted_provider_access_token", self.encrypted_provider_access_token)
		except ConnectionError:
			logger.error(f"unable to set_provider_access_token, retries remaining = {retries}")
			if retries > 0:
				return self.set_provider_access_token(provider_access_token, retries=retries-1)
			return False
		return True

	def set_preferred_volume(self, preferred_volume, retries=1):
		self.preferred_volume = preferred_volume
		try:
			db.hset(f"user:{self.user_id}", "preferred_volume", self.preferred_volume)
		except ConnectionError:
			logger.error(f"unable to set_preferred_volume, retries remaining = {retries}")
			if retries > 0:
				return self.set_preferred_volume(preferred_volume, retries=retries-1)
			return False
		return True

	def set_acct_type(self, acct_type, retries=1):
		self.acct_type = acct_type
		try:
			db.hset(f"user:{self.user_id}", "acct_type", self.acct_type)
		except ConnectionError:
			logger.error(f"unable to set_acct_type, retries remaining = {retries}")
			if retries > 0:
				return self.set_acct_type(acct_type, retries=retries-1)
			return False
		return True

	def clear_tokens(self, vendor, retries=1):
		try:
			# Create transaction
			pipeline = db.pipeline()
			
			if vendor == BOSE_VENDOR_ID:
				# Delete Bose refresh token
				pipeline.hdel(f"user:{self.user_id}", "bose_encrypted_refresh_token")
				self.bose_encrypted_refresh_token = None

				# Delete Bose access token
				pipeline.hdel(f"user:{self.user_id}", "bose_encrypted_access_token")
				self.bose_encrypted_access_token = None

			elif vendor == SONOS_VENDOR_ID:
				# Delete Sonos refresh token
				pipeline.hdel(f"user:{self.user_id}", "sonos_encrypted_refresh_token")
				self.sonos_encrypted_refresh_token = None

				# Delete Sonos access token
				pipeline.hdel(f"user:{self.user_id}", "sonos_encrypted_access_token")
				self.sonos_encrypted_access_token = None

			else:
				return False

			# Execute transaction
			pipeline.execute()
		except ConnectionError:
			logger.error(f"unable to clear {vendor} tokens, retries remaining = {retries}")
			if retries > 0:
				return self.clear_tokens(vendor, retries=retries-1)
			return False
		return True

def validate_google_user(google_token):
	""" validates the google token and returns the email address for the user """
	idinfo = id_token.verify_oauth2_token(google_token, g_requests.Request(), os.environ.get("GOOGLE_OAUTH_CLIENT_ID"))
	logger.debug(idinfo)

	# ID token is valid. Get the user's Google Account email from the decoded token.
	user_email = idinfo['email']
	return user_email

def validate_facebook_user(fb_token, user_id):
	"""validates the facebook token and returns the email address for the user """
	fb_graph_host = "https://graph.facebook.com/"    
	# get app access token
	app_access_url = fb_graph_host + "oauth/access_token?client_id=" + os.environ.get("FB_OAUTH_CLIENT_ID") + "&client_secret=" + os.environ.get("FB_OAUTH_CLIENT_SECRET") + "&grant_type=client_credentials"
	app_access_resp = requests.get(app_access_url)
	app_token = app_access_resp.json()['access_token']

	# fetch info about the supplied user access token
	token_inspect_url = fb_graph_host + "debug_token?input_token=" + fb_token + "&access_token=" + app_token
	token_inspect_resp = requests.get(token_inspect_url)
	token_details = token_inspect_resp.json()
	logger.debug(f"token details: {token_details['data']}")

	# confirm app ID and user ID match 
	if token_details['data']['app_id'] == os.environ.get("FB_OAUTH_CLIENT_ID") and token_details['data']['user_id'] == user_id:
		# use the fb_token (supplied user access token) to get basic user info, return the email address
		email_url = fb_graph_host + "me/?fields=email&access_token=" + fb_token
		email_resp = requests.get(email_url)
		logger.debug(f"email JSON response: {email_resp.json()}")
		return email_resp.json()['email']


	# didn't match, something is up!
	logger.warning(f"Mismatch on token inspection. Supplied app id was {token_details['data']['app_id']}, expected was {os.environ.get('FB_OAUTH_CLIENT_ID')}. Supplied user_id was {token_details['data']['user_id']}, expected was {user_id}.")
	return None

def repair_acct_type(user, silent=False):
	"""
	takes a user without an acct_type, sets the right one, and returns the updated user
	only covers google and bam because acct_type was implemented before facebook
	"""
	if user.encrypted_provider_access_token:
		user.set_acct_type(GOOGLE_ACCT_TYPE)
		logger.debug(f"current user acct type set to: {user.acct_type}")
		if silent:
			return True
		return user
	
	user.set_acct_type(BAM_ACCT_TYPE)
	logger.debug(f"current user acct type set to: {user.acct_type}")
	if silent:
		return True
	return user
