from flask import Flask
from app.routes import main  # ✅ Import your blueprint

def create_app():
    app = Flask(__name__)
    app.secret_key = "secretkey"  # needed for session
    app.register_blueprint(main)       # ✅ Register the blueprint

    return app

