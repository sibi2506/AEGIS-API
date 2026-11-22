from flask import Flask, jsonify, request

app = Flask(__name__)

# Demo credentials for local testing only.
# Never use these credentials in a real application.
DEMO_USERNAME = "student"
DEMO_PASSWORD = "demo123"


@app.route("/")
def home():
    return jsonify({
        "name": "AegisAPI Test API",
        "status": "running"
    })


@app.route("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "message": "Local test API is working"
    })


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({
            "error": "Username and password are required"
        }), 400

    if username == DEMO_USERNAME and password == DEMO_PASSWORD:
        return jsonify({
            "message": "Login successful",
            "token": "demo-token-local-only"
        }), 200

    return jsonify({
        "error": "Invalid username or password"
    }), 401


@app.route("/api/profile", methods=["GET"])
def profile():
    auth_header = request.headers.get("Authorization", "")

    if auth_header != "Bearer demo-token-local-only":
        return jsonify({
            "error": "Authentication required"
        }), 401

    return jsonify({
        "username": DEMO_USERNAME,
        "message": "Authenticated access successful"
    })


@app.route("/api/search")
def search():
    query = request.args.get("q", "")

    if len(query) > 100:
        return jsonify({
            "error": "Search query must be 100 characters or fewer"
        }), 400

    return jsonify({
        "query": query,
        "message": "Search completed"
    })


if __name__ == "__main__":
    print("Starting AegisAPI local security test server...")
    app.run(host="127.0.0.1", port=5000, debug=False)
