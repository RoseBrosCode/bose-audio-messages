import os
from base64 import b64encode, b64decode
from flask import Flask, render_template, redirect, render_template, request, session, url_for
import jinja2
from logging.config import dictConfig
import requests

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

def b64encode_str(s: str) -> str:
    """ Encodes a string to base64 and returns the encoded value as a string. """
    return b64encode(s.encode("utf-8")).decode("utf-8")

def refresh_sb_token():
    """ Refreshes Switchboard Access Token """
    if session['refresh_token'] is None:
        return None
    else:
        t_auth_header = 'Basic ' + b64encode_str(os.environ['SB_CLIENT_ID'] + ':' + os.environ['SB_SECRET'])
        t_headers = {'Authorization':t_auth_header}
        t_data = {'grant_type':'refresh_token', 'refresh_token':session['refresh_token']}
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

# Create flask app
app = Flask(__name__, static_folder="client/public")
app.secret_key = os.environ['SESSION_KEY']

# Set templates dir
app.jinja_loader = jinja2.ChoiceLoader(
    [app.jinja_loader, jinja2.FileSystemLoader("client/templates")])

@app.route('/')
def home_login():

    # First time? Get the login button
    return render_template('home.html')

@app.route('/auth')
def auth_redirect():
    # get Switchboard tokens and put in session
    t_auth_header = 'Basic ' + b64encode_str(os.environ['SB_CLIENT_ID'] + ':' + os.environ['SB_SECRET'])
    t_headers = {'Authorization':t_auth_header}
    t_data = {'grant_type':'authorization_code', 'code':request.args['code'], 'redirect_uri':'http://localhost:5000/auth'}
    tokens = requests.post('https://partners.api.bose.io/auth/oauth/token', headers=t_headers, data=t_data)
    session['access_token'] = tokens.json()['access_token']
    session['refresh_token'] = tokens.json()['refresh_token']

    # Redirect to app
    return redirect(url_for('app_home'))

@app.route('/app')
def app_home():
    
    products_res = get_products(session['access_token'])
    if products_res.status_code == 403:
        if session['refresh_token'] is None:
            return redirect(url_for('home_login'))
        else:
            session['access_token'] = refresh_sb_token()
            products_res = get_products(session['access_token'])

    products_array = products_res.json()['results']

    # image_name_map = {
    #     'Bose Home Speaker 300': 'flipper',
    #     'Bose Home Speaker 450': 'eddie-club',
    #     'Bose Home Speaker 500': 'eddie',
    #     'Bose Soundbar 500': 'professor',
    #     'Bose Soundbar 700': 'g-c',
    #     'Bose Portable Home Speaker': 'taylor'
    # }

    client_products = []
    for p in products_array:
        client_products.append({
            'product_id': p['productID'],
            'product_name': p['productName'],
            'image_name': 'eddie-black' # placeholder for now, when all images are live replace with image_name_map.get(p['productType'], 'default') and uncomment image_name_map
        })

    # List the products
    return render_template('index.html', products=client_products)

@app.route('/send')
def play_msg():

    app.logger.info('Client Message Request Body: ')
    app.logger.info(request.data)

    return ('', 204)