FLASK_NAME = "BAM"
DEFAULT_PREFERRED_VOLUME = 35
BAM_ACCT_TYPE = "bam"
FB_ACCT_TYPE = "fb"
GOOGLE_ACCT_TYPE = "google"
BOSE_VENDOR_ID = "bose"
SONOS_VENDOR_ID = "sonos"
BOSE_AUTH_URL_TEMPLATE = "https://partners.api.bose.io/auth/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope=owned_products_all&state={state}"
SONOS_AUTH_URL_TEMPLATE = "https://api.sonos.com/login/v3/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope=playback-control-all&state={state}"
VENDOR_ID_LIST = [BOSE_VENDOR_ID, SONOS_VENDOR_ID]
