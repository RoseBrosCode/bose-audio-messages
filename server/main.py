from flask import Flask, render_template
import jinja2

# Create flask app
app = Flask(__name__, static_folder="client/public")

# Set templates dir
app.jinja_loader = jinja2.ChoiceLoader(
    [app.jinja_loader, jinja2.FileSystemLoader("client/templates")])

@app.route('/')
def bam():
    return render_template(
        "index.html"
    )
