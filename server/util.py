from base64 import b64encode

def b64encode_str(s: str) -> str:
    """ Encodes a string to base64 and returns the encoded value as a string. """
    return b64encode(s.encode("utf-8")).decode("utf-8")
