import os
import jinja2
import requests
from flask import Flask, render_template, redirect, render_template, request, session, url_for
from logging.config import dictConfig

from switchboard import get_products, refresh_sb_token, send_audio_notification
from util import b64encode_str


# Create flask app
app = Flask(__name__, static_folder="client/public")
app.secret_key = os.environ['SESSION_KEY']

# Set templates dir
app.jinja_loader = jinja2.ChoiceLoader(
    [app.jinja_loader, jinja2.FileSystemLoader("client/templates")])

# Configure logging
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
        'level': os.environ.get("LOG_LEVEL", "INFO"),
        'handlers': ['wsgi']
    }
})

@app.route('/')
def home_login():
    if 'refresh_token' in session:
        return redirect(url_for('app_home'))

    client_id = os.environ['SB_CLIENT_ID']
    redirect_url = os.environ['SB_REDIRECT_URL']

    # First time? Get the login button
    return render_template('home.html', client_id=client_id, redirect_url=redirect_url)

@app.route('/auth')
def auth_redirect():
    # get Switchboard tokens and put in session
    t_auth_header = 'Basic ' + b64encode_str(os.environ['SB_CLIENT_ID'] + ':' + os.environ['SB_SECRET'])
    t_headers = {'Authorization': t_auth_header}
    t_data = {'grant_type':'authorization_code', 'code':request.args['code'], 'redirect_uri':'http://localhost:8000/auth'}
    tokens = requests.post('https://partners.api.bose.io/auth/oauth/token', headers=t_headers, data=t_data)
    session['access_token'] = tokens.json()['access_token']
    session['refresh_token'] = tokens.json()['refresh_token']

    # Redirect to app
    return redirect(url_for('app_home'))

@app.route('/app')
def app_home():
    if 'access_token' in session:
        products_res = get_products(session['access_token'])
        if products_res.status_code == 403:
            if 'refresh_token' in session:
                session['access_token'] = refresh_sb_token()
                products_res = get_products(session['access_token'])
            else:
                return redirect(url_for('home_login'))
                
        products_array = products_res.json()['results']
        app.logger.debug(f"products: {products_array}")

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
                
    else:
        return redirect(url_for('home_login'))

@app.route('/send', methods=['POST'])
def play_msg():
    requested_msg = request.get_json()
    app.logger.debug(requested_msg)
    if 'access_token' in session:
        an_res = send_audio_notification(session['access_token'], requested_msg['target_product'], requested_msg['url'])
        if an_res.status_code == 403:
            if 'refresh_token' in session:
                session['access_token'] = refresh_sb_token()
                an_res = get_products(session['access_token'])
            else:
                return redirect(url_for('home_login'))
                
        app.logger.debug(an_res.json())

        # tell the browser all was fine
        return ('', 204)
                
    else:
        return redirect(url_for('home_login'))
