from flask import request, jsonify, send_from_directory, Blueprint
import jwt
from functools import wraps
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from base64 import b64decode
import json, hashlib
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
import os
from werkzeug.exceptions import RequestEntityTooLarge
from config import MAX_CONTENT_LENGTH, SECRET_KEY, upload_file_metadata, collection_files, FileRetrieval,\
    log_action, UPLOAD_FOLDER, collection_users, get_file_extension

app_routes = Blueprint('app_routes', __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            token = token.split(" ")[1]  # Extract the token part from "Bearer <token>"
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            username = data["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401

        return f(username, *args, **kwargs)
    return decorated


@app_routes.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]
    public_key = data['public_key']

    # Check if user already exists
    if collection_users.find_one({"username": username}):
        return jsonify({"message": "User already exists"}), 409

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Store in MongoDB
    collection_users.insert_one({
        "username": username,
        "password": hashed_password,
        "public_key": public_key,
        "created_at": datetime.now().isoformat()
    })

    return jsonify({"message": "User registered successfully"}), 201


@app_routes.route('/files', methods=['GET'])
@token_required
def list_files(username):
    """List all available files for download."""
    try:
        # Initialize an empty list to hold accessible files
        accessible_files = []

        # Query the database for all files metadata
        all_files = collection_files.find({})

        request_type_dict = request.form.to_dict()  # Convert form data to a dictionary
        request_type = request_type_dict.get('request-type')

        for file_entry in all_files:
            file_path = os.path.basename(file_entry.get('file_path'))
            owner_id = file_entry.get('owner_id')
            shared_with = file_entry.get('shared_with', {})

            if request_type == FileRetrieval.DOWNLOAD.value:
                if username in shared_with or username == owner_id:
                    accessible_files.append(file_path)
            elif request_type == FileRetrieval.SHARE.value:
                if username == owner_id:
                    accessible_files.append(file_path)
            else:
                return jsonify({'error': f"The File Retrieval Type has not been setup correctly. Retrieved an unexpected value"}), 500
        return jsonify(accessible_files)  # Return file names as JSON
    except Exception as e:
        return jsonify({'error': f"Failed to list files. Details: {str(e)}"}), 500

@app_routes.route('/share_file', methods=['POST'])
@token_required
def share_file(username):
    try:
        # Read JSON data from request body
        metadata = request.get_json()
        if not metadata:
            return jsonify({'error': 'No JSON data provided in request body'}), 400

        # Read the signature from headers
        user_signature_b64 = request.headers.get('X-Signature')
        if not user_signature_b64:
            return jsonify({'error': 'Signature missing from request headers'}), 400

        user_signature = b64decode(user_signature_b64)

        # Prepare payload to verify signature (convert metadata dict to JSON string)
        metadata_str = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        payload_to_verify = metadata_str

        user_public_key = get_user_public_key(username)
        if not verify_request_signature(signature=user_signature, payload=payload_to_verify,
                                        public_key=user_public_key):
            return jsonify({"error": "Invalid signature. The file may have been tampered with."}), 400

        # Extract the 'selected_usernames' list from the metadata (assuming the key exists)
        selected_usernames = metadata.get('selected_usernames', [])
        encrypted_symmetric_keys_b64 = metadata.get('encrypted_symmetric_keys', [])
        selected_file_path = metadata.get('file_path')

        try:
            # Attempt to upload file metadata
            file_path = os.path.join(UPLOAD_FOLDER, selected_file_path)
            # the file extension can be whatever you wish. It doesn't matter as this will only update the shared with field along with the last updated.
            # It will not affect the other fields
            upload_file_metadata(file_path=file_path,owner_id=username, original_file_extension=None, shared_symmetric_keys=encrypted_symmetric_keys_b64)
        except Exception as e:
            # Handle any error that occurs and print a meaningful message
            return jsonify({'error': f"Failed to upload the file metadata. Details: {str(e)}"}), 400
        # Join the usernames into a comma-separated string
        username_strings = ', '.join(selected_usernames)
        return jsonify({
            "message": f"Files where successfully shared with users: {username_strings}"
        }), 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 400

@app_routes.route('/login', methods=['POST'])
def login():
    # Get the data from the request
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Find the user in the database
    user = collection_users.find_one({"username": username})

    if user is None:
        return jsonify({"message": "User not found"}), 404

    # Check the hashed password
    if check_password_hash(user['password'], password):
        log_action(username, "Login")
        token = jwt.encode(
            {'username': username, "exp": datetime.now() + timedelta(hours=1)},
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"message": "Login successful!", "token": token}), 200
    else:
        return jsonify({"message": "Incorrect Password"}), 401


def get_user_public_key(username):
    """
    Retrieve and load the user's public key from the database.

    :param username: The username of the user whose public key is being retrieved.
    :return: The loaded public key object.
    :raises: KeyError if the user does not exist, ValueError if the key format is invalid.
    """
    # Query the database for the user data
    user_data = collection_users.find_one({"username": username})
    if not user_data:
        raise KeyError(f"Couldn't find user with username: {username}")

    # Retrieve the public key as a string (base64 or PEM)
    public_key_base64 = user_data.get('public_key')
    if not public_key_base64:
        raise ValueError(f"No public key found for user: {username}")

    try:
        public_key_bytes = b64decode(public_key_base64)  # Decode from base64
        public_key = serialization.load_pem_public_key(public_key_bytes)  # Load PEM public key
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to load public key for user: {username}. Error: {e}")


@app_routes.route('/upload', methods=['POST'])
@token_required
def upload(username):
    if 'file' not in request.files:
        return jsonify({'error': "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400

    try:
        metadata = request.form.to_dict()
        user_signature_b64 = request.headers.get('X-Signature')
        if not user_signature_b64:
            return jsonify({'error': 'Signature missing from request headers'}), 400

        user_signature = b64decode(user_signature_b64)
        metadata_str = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        payload_to_verify = metadata_str

        user_public_key = get_user_public_key(username)
        # Compare the hashes to ensure that no data was lost during transmission/encryption-decryption
        metadata_file_hash = metadata.get('hashed_file')
        # Since the file on the server hasn't been saved yet, we cannot use the same function as before to generate the hash
        # We need to generate the hash from the stream and then compare the two.
        computed_file_hash  = generate_file_hash_from_stream(file)
        if not computed_file_hash == metadata_file_hash:
            print("Cannot verify hash integrity. File may has been tampered with. Aborting... metadata_file_hash: {metadata_file_hash} != {computed_file_hash}: computed_file_hash")
            return jsonify({"error": "Cannot verify hash integrity. The file may have been tampered with."}), 400

        if not verify_request_signature(signature=user_signature, payload=payload_to_verify, public_key=user_public_key):
            return jsonify({"error": "Invalid signature. The file may have been tampered with."}), 400

        original_filename = secure_filename(os.path.basename(file.filename))
        file_path = os.path.join(UPLOAD_FOLDER, original_filename)
        # file_path = os.path.normpath(os.path.join(UPLOAD_FOLDER, original_filename))
        file.save(file_path)  # Save the uploaded file

        original_file_extension = metadata.get('original_file_extension')

        # Log the upload action
        try:
            log_action(
                username,
                "Upload",
                original_filename
            )
        except Exception as e:
            print(f"Error calling log_action: {str(e)}")

        upload_file_metadata(file_path=file_path, owner_id=username, original_file_extension=original_file_extension,shared_symmetric_keys={})

        return jsonify({
            "message": "File uploaded and encrypted successfully",
            "original_filename": original_filename,
            "server_stored_path": file_path
        }), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app_routes.route('/download/<filename>', methods=['GET'])
@token_required
def download(username, filename):
    user_signature_b64 = request.headers.get('X-Signature')
    if not user_signature_b64:
        return jsonify({'error': 'Signature missing from request headers'}), 400

    metadata_json = request.form.to_dict()
    user_signature = b64decode(user_signature_b64)
    metadata = json.dumps(metadata_json, separators=(',', ':')).encode('utf-8')
    payload_to_verify = metadata

    public_key = get_user_public_key(username)

    if not verify_request_signature(signature=user_signature, payload=payload_to_verify, public_key=public_key):
        return jsonify({"error": "Invalid signature. The file may have been tampered with."}), 400

    return send_from_directory(os.path.normpath(UPLOAD_FOLDER), filename, as_attachment=True)


@app_routes.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return jsonify({
        "error": f"File is too large. The maximum allowed size is {MAX_CONTENT_LENGTH // 1024}"
    }), 413

def verify_request_signature(signature, payload, public_key):
    """
    Verify the signature of the payload using the provided public key.

    :param signature: The signature to verify.
    :param payload: The data to verify the signature against.
    :param public_key: The public key to verify the signature with.
    :return: True if verification is successful, False otherwise.
    """
    print("Public Key Type:", type(public_key))  # Log the type of the public key to ensure it's an RSAPublicKey
    print("Payload:", payload)  # Log the payload being verified
    # print("Signature (Base64-decoded):", signature)  # Log the decoded signature
    try:

        public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        print(f"Exception Type: {type(e)}")
        return False

def generate_file_hash_from_stream(file):
    """Generate SHA-256 hash directly from the uploaded file stream."""
    hasher = hashlib.sha256()
    # Read the file in chunks to avoid memory issues with large files
    for chunk in iter(lambda: file.read(4096), b""):
        hasher.update(chunk)
    # Reset file pointer after reading to allow other operations on the file
    file.seek(0)
    return hasher.hexdigest()

@app_routes.route('/retrieve_all_usernames', methods=['POST'])
def retrieve_all_usernames():
    try:
        # Retrieve all usernames from the collection and exclude the _id field
        users = collection_users.find({}, {'_id': 0, 'username': 1})

        # Create a list of usernames
        usernames = [user['username'] for user in users]

        # Return the list of usernames as a JSON response
        return jsonify(usernames), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500