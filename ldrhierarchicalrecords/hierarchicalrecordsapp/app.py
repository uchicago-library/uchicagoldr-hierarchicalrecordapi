from flask import Flask

from ldrhierarchicalrecords.hierarchicalrecordsapi.api import BP

app = Flask(__name__)
app.register_blueprint(BP)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response
