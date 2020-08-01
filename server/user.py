import os
import redis
import logging
import uuid

from flask import flash
from flask_login import UserMixin, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from redis.exceptions import LockError
from cryptography.fernet import Fernet, InvalidToken
from google.oauth2 import id_token
from google.auth.transport import requests

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

    def __init__(self, user_id, username, password_hash, encrypted_provider_access_token, acct_type="bam", encrypted_refresh_token=None, encrypted_access_token=None, preferred_volume=DEFAULT_PREFERRED_VOLUME):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.encrypted_provider_access_token = encrypted_provider_access_token
        self.acct_type = acct_type
        self.encrypted_refresh_token = encrypted_refresh_token
        self.encrypted_access_token = encrypted_access_token
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
                    d.get("acct_type", None), d.get("encrypted_refresh_token", None), d.get("encrypted_access_token", None), d.get("preferred_volume", None))

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
    def create_user(username, password=None, provider_access_token=None, acct_type="bam", retries=1):
        """Creates a new user and stores it in Redis."""
        # Case insensitive usernames
        username_lower = username.lower()
        logger.debug(f"username_lower: {username_lower}")

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

                # TODO: add password_hash and encrypted_provider_access_token to user_dict
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
        logger.debug("in username exists")

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

    def get_refresh_token(self):
        if self.encrypted_refresh_token:
            return secret_key.decrypt(self.encrypted_refresh_token.encode()).decode()
        return None

    def set_refresh_token(self, refresh_token, retries=1):
        self.encrypted_refresh_token = secret_key.encrypt(refresh_token.encode())
        try:
            db.hset(f"user:{self.user_id}", "encrypted_refresh_token", self.encrypted_refresh_token)
        except ConnectionError:
            logger.error(f"unable to set_refresh_token, retries remaining = {retries}")
            if retries > 0:
                return self.set_refresh_token(refresh_token, retries=retries-1)
            return False
        return True

    def get_access_token(self):
        if self.encrypted_access_token:
            return secret_key.decrypt(self.encrypted_access_token.encode()).decode()
        return None

    def set_access_token(self, access_token, retries=1):
        self.encrypted_access_token = secret_key.encrypt(access_token.encode())
        try:
            db.hset(f"user:{self.user_id}", "encrypted_access_token", self.encrypted_access_token)
        except ConnectionError:
            logger.error(f"unable to set_access_token, retries remaining = {retries}")
            if retries > 0:
                return self.set_access_token(access_token, retries=retries-1)
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

    def clear_tokens(self, retries=1):
        try:
            # Create transaction
            pipeline = db.pipeline()

            # Delete refresh token
            pipeline.hdel(f"user:{self.user_id}", "encrypted_refresh_token")

            # Delete access token
            pipeline.hdel(f"user:{self.user_id}", "encrypted_access_token")

            # Execute transaction
            pipeline.execute()
        except ConnectionError:
            logger.error(f"unable to clear_tokens, retries remaining = {retries}")
            if retries > 0:
                return self.clear_tokens(retries=retries-1)
            return False
        return True

def validate_google_user(google_token):
    """ validates the google token and returns the email address for the user """
    idinfo = id_token.verify_oauth2_token(google_token, requests.Request(), os.environ.get("GOOGLE_OAUTH_CLIENT_ID"))
    logger.debug(idinfo)

    # ID token is valid. Get the user's Google Account email from the decoded token.
    user_email = idinfo['email']
    return user_email

def repair_acct_type(user, silent=False):
    """ takes a user without an acct_type, sets the right one, and returns the updated user """
    if user.encrypted_provider_access_token:
        user.set_acct_type("google")
        logger.debug(f"current user acct type set to: {user.acct_type}")
        if silent:
            return True
        return user
    
    user.set_acct_type("bam")
    logger.debug(f"current user acct type set to: {user.acct_type}")
    if silent:
        return True
    return user
