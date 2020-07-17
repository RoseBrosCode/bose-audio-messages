import os
import redis
import logging
import uuid

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from redis.exceptions import LockError
from cryptography.fernet import Fernet, InvalidToken

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

    def __init__(self, user_id, username, password_hash, encrypted_refresh_token=None, encrypted_access_token=None):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.encrypted_refresh_token = encrypted_refresh_token
        self.encrypted_access_token = encrypted_access_token

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
        return User(d["user_id"], d["username"], d["password_hash"], 
                    d.get("encrypted_refresh_token", None), d.get("encrypted_access_token", None))

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
    def create_user(username, password, retries=1):
        """Creates a new user and stores it in Redis."""
        # Case insensitive usernames
        username_lower = username.lower()

        try:
            with db.lock("user_lock", blocking_timeout=1) as lock:
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
                password_hash = generate_password_hash(password)
                user_dict = {
                    "user_id": user_id,
                    "username": username_lower,
                    "password_hash": password_hash
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

        with db.lock("user_lock", blocking_timeout=1) as lock:
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

    def set_refresh_token(self, refresh_token):
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
                return self.set_access_token(access_token, retries=retries-1)
            return False
        return True
