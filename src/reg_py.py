from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import bcrypt
import cx_Oracle
import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64


app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:5173"])

users = {}  # Store user encryption keys
user_sessions = {}  # Store session IDs for each user
groups = {}


# Database connection setup
def connect_db():
    try:
        dsn_tns = cx_Oracle.makedsn(
            os.getenv('DB_HOST', 'localhost'),
            os.getenv('DB_PORT', '1521'),
            service_name=os.getenv('DB_SERVICE_NAME', 'XEPDB1')
        )
        conn = cx_Oracle.connect(
            user=os.getenv('DB_USER', 'system'),
            password=os.getenv('DB_PASSWORD', 'passwordd'),
            dsn=dsn_tns
        )
        return conn
    except cx_Oracle.DatabaseError as e:
        print("Database connection error:", e)
        return None
    
@app.route('/chat_history', methods=['GET'])
def get_chat_history():
    username = request.args.get('username')  # Logged-in user
    other_user = request.args.get('other_user')  # Selected user to chat with

    conn = connect_db()
    try:
        with conn.cursor() as cursor:
            # Fetch messages where sender is either username or other_user
            query = """
            SELECT sender, MESSAGE_TEXT, ENCRYPTED_AES_KEY, enc_aes_key_sender, type
            FROM messages
            WHERE (sender = :1 AND receiver = :2) OR (sender = :2 AND receiver = :1)
            ORDER BY message_id ASC
            """
            cursor.execute(query, (username, other_user))

            messages = []
            for row in cursor.fetchall():
                sender = row[0]
                # Read the LOBs properly
                message_text = row[1].read() if hasattr(row[1], 'read') else row[1]
                encrypted_aes_key = row[2].read() if hasattr(row[2], 'read') else row[2]
                enc_aes_key_sender = row[3].read() if hasattr(row[3], 'read') else row[3]
                type = row[4].read() if hasattr(row[4], 'read') else row[4]

                # Convert bytes to string if necessary
                if isinstance(message_text, bytes):
                    message_text = message_text.decode('utf-8')
                if isinstance(encrypted_aes_key, bytes):
                    encrypted_aes_key = encrypted_aes_key.decode('utf-8')
                if isinstance(enc_aes_key_sender, bytes):
                    enc_aes_key_sender = enc_aes_key_sender.decode('utf-8')
                if isinstance(type, bytes):
                    type = type.decode('utf-8')

                # Choose the appropriate AES key based on whether the user is the sender or receiver
                encrypt_aes_key = enc_aes_key_sender if sender == username else encrypted_aes_key

                messages.append({
                    "sender": sender,
                    "message": message_text,
                    "aesKey": encrypt_aes_key, 
                    "type": type #Include the correct encrypted AES key
                })

        return jsonify(messages), 200
    except Exception as e:
        print("Error fetching chat history:", e)
        return jsonify({"message": "An error occurred"}), 500
    finally:
        conn.close()
        

@app.route('/group_chat_history', methods=['GET'])
def get_group_chat_history():
    group_name = request.args.get('group_name')  # Name of the selected group

    conn = connect_db()
    try:
        with conn.cursor() as cursor:
            # Fetch messages where group_name matches the specified group
            query = """
            SELECT sender, MESSAGE_TEXT, ENCRYPTED_AES_KEY, type
            FROM group_messages
            WHERE group_name = :1
            ORDER BY message_id ASC
            """
            cursor.execute(query, (group_name,))

            messages = []
            for row in cursor.fetchall():
                sender = row[0]
                # Read the LOBs properly
                message_text = row[1].read() if hasattr(row[1], 'read') else row[1]
                encrypted_aes_key = row[2].read() if hasattr(row[2], 'read') else row[2]
                type = row[3].read() if hasattr(row[3], 'read') else row[3]

                # Convert bytes to string if necessary
                if isinstance(message_text, bytes):
                    message_text = message_text.decode('utf-8')
                if isinstance(encrypted_aes_key, bytes):
                    encrypted_aes_key = encrypted_aes_key.decode('utf-8')
                if isinstance(type, bytes):
                    type = type.decode('utf-8')
                
                

                messages.append({
                    "sender": sender,
                    "message": message_text,
                    "aesKey": encrypted_aes_key,
                    "type": type
                })

        return jsonify(messages), 200
    except Exception as e:
        print("Error fetching group chat history:", e)
        return jsonify({"message": "An error occurred"}), 500
    finally:
        conn.close()




# Route to register users
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO chat_users (username, password) VALUES (:1, :2)", (username, hashed_password))
            conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except cx_Oracle.IntegrityError:
        return jsonify({"message": "Username already exists"}), 409
    except Exception as e:
        print("Error during registration:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500
    finally:
        conn.close()


@socketio.on('create_group')
def handle_create_group(data):
    group_name = data['groupName']
    members = data['members']

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            # Insert into groups table
            cursor.execute("INSERT INTO groups (group_name) VALUES (:group_name)", {'group_name': group_name})
            conn.commit()  # Commit to make the group ID visible for next query

            # Get the group ID of the newly created group
            cursor.execute("SELECT group_id FROM groups WHERE group_name = :group_name", {'group_name': group_name})
            group_id_result = cursor.fetchone()
            
            if not group_id_result:
                raise ValueError("Group ID not found after group creation")
            
            group_id = group_id_result[0]
            print(f"New group ID: {group_id}")

            # Insert members into group_members table
            for member in members:
                    try:
                        cursor.execute(
                            "INSERT INTO group_members (group_id, username) VALUES (:group_id, :username)",
                            {'group_id': group_id, 'username': member}
                        )
                    except cx_Oracle.DatabaseError as e:
                        error, = e.args
                        print(f"Failed to insert member '{member}': {error.message}")
                        emit('error', {'message': f"Failed to add member '{member}' to the group."})

            # Commit the transaction
            conn.commit()

            # Store group in memory
            groups[group_name] = members

            print(f'Group created: {group_name} with members: {members}')

    except cx_Oracle.DatabaseError as e:
        error, = e.args
        print(f'Database Error: {error.message}')
        emit('error', {'message': 'An error occurred while creating the group.'})
        conn.rollback()  # Rollback on error

    except Exception as e:
        print(f"General error: {e}")
        emit('error', {'message': 'An unexpected error occurred.'})
        conn.rollback()

    finally:
        conn.close()

        
# Route to store public key
@app.route('/api/storePublicKey', methods=['POST'])
def store_public_key():
    data = request.get_json()
    username = data['username']
    public_key = data['publicKey']

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            # Store the public key in the database
            cursor.execute("UPDATE chat_users SET public_key = :1 WHERE username = :2", (public_key, username))
            conn.commit()
        return jsonify({"message": "Public key stored successfully"}), 200
    except Exception as e:
        print("Error storing public key:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# Route to log in users
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT password FROM chat_users WHERE username = :1", (username,))
            result = cursor.fetchone()
            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                session_id = Fernet.generate_key().decode()  # Session ID is a Fernet key
                user_sessions[username] = session_id
                return jsonify({"message": "Login successful", "session_id": session_id}), 200
            else:
                return jsonify({"message": "Invalid credentials"}), 401
    except Exception as e:
        print("Error during login:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500
    finally:
        conn.close()

@app.route('/users', methods=['GET'])
def search_users():
    search_term = request.args.get('search', '')
    current_user = request.args.get('current_user', '')
    like_pattern = f"%{search_term}%"

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            # Fetch individual users
            cursor.execute("SELECT username FROM chat_users WHERE username LIKE :1", (like_pattern,))
            users = [row[0] for row in cursor.fetchall()]

            # Fetch group names where the current user is a member
            cursor.execute("""
                SELECT g.group_name 
                FROM groups g
                JOIN group_members gm ON g.group_id = gm.group_id
                WHERE gm.username = :current_user
                AND g.group_name LIKE :like_pattern
            """, {'current_user': current_user, 'like_pattern': like_pattern})
            groups = [f"{row[0]} (Group)" for row in cursor.fetchall()]

        # Combine users and groups into a single list
        result = users + groups
        return jsonify(result)

    except Exception as e:
        print("Error during user and group search:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500

    finally:
        conn.close()



        
@app.route('/getPublicKey/<username>', methods=['GET'])
def get_public_key(username):
    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT public_key FROM chat_users WHERE username = :1", (username,))
            result = cursor.fetchone()
            if result:
                public_key_clob = result[0]  # Assuming public_key is in the first column
                public_key = public_key_clob.read() if hasattr(public_key_clob, 'read') else public_key_clob
                return jsonify({"publicKey": public_key}), 200
            else:
                return jsonify({"message": "User not found"}), 404
    except Exception as e:
        print("Error fetching public key:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500
    finally:
        conn.close()

@app.route('/groups/members', methods=['GET'])
def get_group_members():
    group_name = request.args.get('groupName', '')

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            # First, get the GROUP_ID for the specified group name
            cursor.execute("SELECT GROUP_ID FROM groups WHERE GROUP_NAME = :1", (group_name,))
            group_id_row = cursor.fetchone()
            
            if not group_id_row:
                return jsonify({"message": "Group not found"}), 404
            
            group_id = group_id_row[0]

            # Now get the members in the group using the GROUP_ID
            cursor.execute("SELECT USERNAME FROM group_members WHERE GROUP_ID = :1", (group_id,))
            members = [row[0] for row in cursor.fetchall()]

        # Return the list of members
        return jsonify({"members": members})

    except Exception as e:
        print("Error fetching group members:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500

    finally:
        conn.close()
        
        
@app.route('/check_password', methods=['GET'])
def check_password():
    logged_in_user = request.args.get('logged_in_user')
    selected_user = request.args.get('selected_user')

    if not logged_in_user or not selected_user:
        return jsonify({"error": "Missing parameters"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"message": "Database connection error"}), 500

    try:
        with conn.cursor() as cursor:
            # Query to check if a password exists for the given users
            cursor.execute("""
                SELECT password_hash
                FROM chat_passwords
                WHERE username = :1 AND chat_user = :2
            """, (logged_in_user, selected_user))

            result = cursor.fetchone()

            # If no result found, return False for password
            if not result:
                return jsonify({"password": False})

            # Check if the result has a password hash
            if result[0]:
                return jsonify({"password": True})
            else:
                return jsonify({"password": False})

    except Exception as e:
        print("Error checking password:", e)
        return jsonify({"message": "An unexpected error occurred"}), 500

    finally:
        conn.close()
        

@app.route('/set_password', methods=['POST'])
def set_password():
    # Get the data from the request body
    data = request.get_json()
    logged_in_user = data.get('logged_in_user')
    selected_user = data.get('selected_user')
    password = data.get('password')

    # Check if the parameters are provided
    if not logged_in_user or not selected_user or not password:
        return jsonify({"error": "Missing parameters"}), 400

    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Connect to the database
    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with conn.cursor() as cursor:
            # Insert or update the password in the chat_passwords table
            sql_query = """
                INSERT INTO chat_passwords (username, chat_user, password_hash)
                VALUES (:logged_in_user, :selected_user, :password)
                """
            cursor.execute(sql_query, {
                'logged_in_user': logged_in_user,
                'selected_user': selected_user,
                'password': hashed_password
            })
            conn.commit()

        return jsonify({"message": "Password set successfully!"})

    except cx_Oracle.DatabaseError as e:
        error, = e.args
        return jsonify({"error": f"Database error: {error.message}"}), 500

    finally:
        # Ensure that the connection is closed after the query
        conn.close()



@app.route('/verify_password', methods=['POST'])
def verify_password():
    # Get the data from the request body
    data = request.get_json()
    logged_in_user = data.get('logged_in_user')
    selected_user = data.get('selected_user')
    password = data.get('password')

    # Check if the parameters are provided
    if not logged_in_user or not selected_user or not password:
        return jsonify({"error": "Missing parameters"}), 400

    # Hash the provided password using SHA-256
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Connect to the database
    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with conn.cursor() as cursor:
            # Fetch the stored password hash for the given user pair (logged_in_user, selected_user)
            sql_query = """
                SELECT password_hash
                FROM chat_passwords
                WHERE username = :logged_in_user AND chat_user = :selected_user
            """
            cursor.execute(sql_query, {'logged_in_user': logged_in_user, 'selected_user': selected_user})

            # Fetch the result
            result = cursor.fetchone()

            # If the result exists, compare the hashes
            if result and result[0]:
                stored_password_hash = result[0]

                # Compare the hashed passwords
                if hashed_password == stored_password_hash:
                    return jsonify({"isValid": True})  # Passwords match
                else:
                    return jsonify({"isValid": False})  # Passwords do not match
            else:
                return jsonify({"error": "No password set for this user pair"}), 404

    except cx_Oracle.DatabaseError as e:
        error, = e.args
        return jsonify({"error": f"Database error: {error.message}"}), 500

    finally:
        # Ensure that the connection is closed after the query
        conn.close()



# Socket events for real-time communication
@socketio.on('connect')
def handle_connect():
    username = request.args.get('username')
    if username:
        join_room(username)  # User joins a room with their username
        print(f"{username} has joined their room.")

@socketio.on('disconnect')
def handle_disconnect():
    username = request.args.get('username')
    if username:
        leave_room(username)  # Optional: Remove user from their room
        print(f"{username} has disconnected.")

# Socket events for real-time communication
@socketio.on('send_message')
def handle_send_message(data):
    receiver = data['receiver']
    message = data['message']
    sender = data['sender']
    aesKey = data['EaesKey']
    raesKey = data['Raeskey']
    key = data['key']
    type = data['type']
   
    

    # Connect to the database to retrieve the sender's password
    conn = connect_db()
    if conn:
        try:
            with conn.cursor() as cursor:
                    
                    cursor.execute("INSERT INTO messages (sender, receiver, MESSAGE_TEXT, encrypted_aes_key, enc_aes_key_sender, type) VALUES (:1, :2, :3, :5, :6, :7)", (sender, receiver, message, raesKey, aesKey, type))
                    conn.commit()
                
        
        except Exception as e:
            print("Error storing message:", e)
            print("Key:",key)
        finally:
            conn.close()
        
        emit('receive_message', {"sender": sender, "message":message, "aesKey":raesKey}, room=receiver)
    else:
        print("Error: Database connection could not be established.")

@socketio.on('send_image')
def handle_send_image(data):
    receiver = data['receiver']
    message = data['message']
    sender = data['sender']
    aesKey = data['aesKey']
    raesKey = data['raesKey']
    type = data['type']
    
    # Connect to the database to retrieve the sender's password
    conn = connect_db()
    if conn:
        try:
            with conn.cursor() as cursor:
                    
                    cursor.execute("INSERT INTO messages (sender, receiver, MESSAGE_TEXT, encrypted_aes_key, enc_aes_key_sender, type) VALUES (:1, :2, :3, :5, :6, :7)", (sender, receiver, message, raesKey, aesKey, type))
                    conn.commit()
                
        
        except Exception as e:
            print("Error storing message:", e)
           
        finally:
            conn.close()
        
        emit('receive_image', {"sender": sender, "message":message, "aesKey":raesKey}, room=receiver)
    else:
        print("Error: Database connection could not be established.")


@socketio.on('send_group_image')
def handle_send_image(data):
    receiver = data['receiver']
    message = data['message']
    sender = data['sender']
    aesKey = data['aesKey']
    raesKey = data['raesKey']
    group = data['group_name']
    type = data['type']
    
    
    # Connect to the database to retrieve the sender's password
    conn = connect_db()
    if conn:
        try:
            with conn.cursor() as cursor:
                    
                    cursor.execute("INSERT INTO messages (sender, receiver, MESSAGE_TEXT, encrypted_aes_key, enc_aes_key_sender, group_name, type) VALUES (:1, :2, :3, :5, :6, :7, :8)", (sender, receiver, message, raesKey, aesKey, group, type))
                    conn.commit()
                
        
        except Exception as e:
            print("Error storing message:", e)
           
        finally:
            conn.close()
        
        emit('receive_group_image', {"sender": sender, "message":message, "aesKey":raesKey, "group": group}, room=receiver)
    else:
        print("Error: Database connection could not be established.")
        
        
@socketio.on('send_group_message')
def handle_send_message(data):
    receiver = data['receiver']
    message = data['message']
    sender = data['sender']
    aesKey = data['EaesKey']
    raesKey = data['Raeskey']
    key = data['key']
    group = data['group_name']
    type = data['type']
   
    

    # Connect to the database to retrieve the sender's password
    conn = connect_db()
    if conn:
        try:
            with conn.cursor() as cursor:
                    
                    cursor.execute("INSERT INTO group_messages (sender, receiver, MESSAGE_TEXT, encrypted_aes_key, enc_aes_key_sender, group_name, type) VALUES (:1, :2, :3, :5, :6, :7, :8)", (sender, receiver, message, raesKey, aesKey, group, type))
                    conn.commit()
                
        
        except Exception as e:
            print("Error storing message:", e)
            print("Key:",key)
        finally:
            conn.close()
        
        emit('receive_group_message', {"sender": sender, "message":message, "aesKey":raesKey, "group":group}, room=receiver)
    else:
        print("Error: Database connection could not be established.")







if __name__ == "__main__":
    socketio.run(app, host="localhost", port=5000)
