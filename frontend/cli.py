from flask import Flask, request, jsonify
import redis
import psycopg2
import os
import random
import secrets
import string
from werkzeug.security import generate_password_hash , check_password_hash
from psycopg2.errors import IntegrityError
import hashlib, random
import uuid

app = Flask(__name__)


# Connect to Redis
redis_client = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)

def generate_unique_snippet_id():
    while True:
        snippet_id = hashlib.md5(str(random.random()).encode()).hexdigest()[:10]
        cursor.execute("SELECT 1 FROM snippets WHERE snippet_id = %s;", (snippet_id,))
        if cursor.fetchone() is None:  # If not found, it's unique
            return snippet_id


# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname="snippets",
    user="admin",
    password="secret",
    host="localhost",
    port="5432"
    
)
cursor = conn.cursor()
'''
@app.route("/snippets", methods=["POST"])
def create_snippet():
    data = request.json
    token = request.headers.get("Authorization")

    if not redis_client.exists(token):
        return jsonify({"error": "Invalid API token"}), 401

    cursor.execute(
        "INSERT INTO snippets (content, visibility) VALUES (%s, %s) RETURNING id;",
        (data["content"], data["is_private"])
    )
    snippet_id = cursor.fetchone()[0]
    conn.commit()

    return jsonify({"url": f"http://localhost:5000/snippets/{snippet_id}"})
'''

@app.route("/snippets", methods=["POST"])
def create_snippet():
    data = request.json
    token = request.headers.get("Authorization")
    snippet_id = generate_unique_snippet_id()
    # Validate API token
    if not redis_client.exists(token):
        return jsonify({"error": "Invalid API token"}), 401

    # Retrieve login_token from Redis
    login_token = redis_client.get(token)

    # Convert boolean to "private" or "public"
    visibility = "private" if data.get("is_private", True) else "public"

    # Insert into database
    cursor.execute(
        "INSERT INTO snippets (snippet_id ,snippet, login_token, visibility) VALUES (%s , %s, %s, %s) RETURNING snippet_id;",
        (snippet_id ,data["content"], login_token, visibility)
    )
    snippet_id = cursor.fetchone()[0]
    conn.commit()

    return jsonify({"url": f"http://localhost:5000/snippets/{snippet_id}"})


@app.route("/snippets/<snippet_id>", methods=["GET"])
def get_snippet(snippet_id):
    token = request.args.get("public_key")  # Extract public_key from URL

    # Fetch snippet details from the database
    cursor.execute("SELECT snippet, visibility, login_token FROM snippets WHERE snippet_id = %s;", (snippet_id,))
    snippet_data = cursor.fetchone()

    if not snippet_data:
        return jsonify({"error": "Snippet not found"}), 404

    snippet, visibility, login_token = snippet_data

    # If private, require a valid public_key
    if visibility == "private":
        if not token:  # If no token is provided, reject the request
            return jsonify({"error": "Public key required for private snippet"}), 401
        
        public_key = redis_client.get(token)
        
        if not public_key:  # Token not found in Redis (expired or invalid)
            return jsonify({"error": "Invalid or expired public key"}), 403

        public_key = public_key # Decode from bytes to string

        if public_key != str(login_token):  # Ensure it matches login_token
            return jsonify({"error": "Invalid public key"}), 403

    return jsonify({"snippet": snippet, "visibility": visibility})


# Add this route before if __name__ == "__main__":
@app.route("/snippets/<snippet_id>/delete", methods=["POST"])
def delete_snippet(snippet_id):
    # Get authorization token from headers
    token = request.headers.get("Authorization")
    
    if not token:
        return jsonify({"error": "Authorization token required"}), 401
    
    # Validate API token
    if not redis_client.exists(token):
        return jsonify({"error": "Invalid API token"}), 401
        
    # Get the login_token associated with the session token
    user_login_token = redis_client.get(token)
    
    try:
        # Check if snippet exists and belongs to user
        cursor.execute(
            "SELECT login_token FROM snippets WHERE snippet_id = %s;",
            (snippet_id,)
        )
        result = cursor.fetchone()
        
        if not result:
            return jsonify({"error": "Snippet not found"}), 404
            
        snippet_login_token = result[0]
        
        # Verify ownership
        if str(snippet_login_token) != str(user_login_token):
            return jsonify({"error": "Unauthorized to delete this snippet"}), 403
            
        # Delete the snippet
        cursor.execute(
            "DELETE FROM snippets WHERE snippet_id = %s AND login_token = %s;",
            (snippet_id, user_login_token)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"error": "Delete operation failed"}), 500
        
        return jsonify({"message": "Snippet deleted successfully"}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/signin", methods=["POST"])
def signin():
    username = request.json["Username"]
    password = request.json["Password"]

    # Fetch stored password hash & login_token
    cursor.execute("SELECT password, login_token FROM signin WHERE username = %s;", (username,))
    user = cursor.fetchone()

    if user is None or not check_password_hash(user[0], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Generate session token
    session_token = secrets.token_urlsafe(16)

    # Store session token mapped to the user's login_token
    redis_client.set(session_token, user[1], ex=6000)  # Store login_token, not "authenticated"

    return jsonify({"token": session_token}),200



# Backend code modification needed
@app.route("/create_account", methods=["POST"])
def create_account():
    try:
        data = request.json
        username = data["Username"]
        password = generate_password_hash(data["Password"])
        email = data["Email"]
        # Generate login_token as a standard UUID string
        login_token = str(uuid.uuid4())  # Convert UUID to string

        cursor.execute(
            "INSERT INTO signin (username, password, email, login_token) VALUES (%s, %s, %s, %s);",
            (username, password, email, login_token)
        )
        
        conn.commit()
        return jsonify({"message": "Account created successfully"})

    except IntegrityError as e:
        conn.rollback()
        return jsonify({"error": "Email already exists"}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500



@app.route("/snippets/list", methods=["GET"])
def list_snippets():
    # Get authorization token from headers
    token = request.headers.get("Authorization")
    
    # Validate API token
    if not redis_client.exists(token):
        return jsonify({"error": "Invalid API token"}), 401
        
    # Get the login_token associated with the session token
    user_login_token = redis_client.get(token)
    
    # Fetch all snippets for the user
    cursor.execute(
        "SELECT snippet_id, snippet, visibility, created_at FROM snippets WHERE login_token = %s ORDER BY created_at DESC;",
        (user_login_token,)
    )
    snippets = cursor.fetchall()
    
    # Format the response
    snippet_list = [{
        "id": snippet[0],
        "content": snippet[1],
        "visibility": snippet[2],
        "created_at": snippet[3].isoformat() if snippet[3] else None
    } for snippet in snippets]
    
    return jsonify({
        "snippets": snippet_list,
        "count": len(snippet_list)
    })


'''
@app.route("/create_account", methods=["POST"])
def create_account():
    username = request.json["Username"]
    password = request.json["Password"]
    email = request.json["Email"]
    cursor.execute("INSERT INTO signin (username, password, email) VALUES (%s, %s,%s);", (username, password , email))
    conn.commit()
    return jsonify({"message": "Account created"})
'''
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    
    
 
