from flask import Flask
app = Flask(__name__)

@app.route('/')
def projects():
    return 'The index page'

@app.route('/about')
def about():
    return 'The about page'