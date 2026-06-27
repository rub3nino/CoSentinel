from flask import Flask, request
from flask_cors import CORS
import jwt

from settings import SECRET_KEY

app = Flask(__name__)
app.config["DEBUG"] = True
app.secret_key = SECRET_KEY
CORS(app, origins="*")


@app.route("/admin/dashboard")
def admin_dashboard():
    return "admin panel"


@app.route("/debug/trace")
def debug_trace():
    return repr(request.headers)


@app.route("/api/login")
def login():
    token = request.args.get("token", "")
    jwt.decode(token, options={"verify_signature": False})
    return {"ok": True}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
