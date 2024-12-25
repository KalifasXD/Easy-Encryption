import datetime, requests, base64, json
from enum import Enum

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import win32crypt, os, zipfile, tarfile
from pymongo import MongoClient

MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500 MB LIMIT
UPLOAD_FOLDER = 'uploads'
MONGO_URI = "mongodb+srv://vasilis944:qEmWxlrXh2Hlssf1@cluster0.z56q5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
SECRET_KEY = os.getenv("ENCRYPTION_KEY")
saved_token = ''

# Connect to MongoDB
client = MongoClient(MONGO_URI)


# Mongo DB Settings
database_name = 'secure_file_transfer'
users_collection_names = 'users'
action_logs_collection_names = 'action_logs'
uploaded_files_collection_names = 'uploaded_files'

# Access the database
db = client[database_name]

# Access a collection
collection_users = db[users_collection_names]
collection_users.create_index("username", unique=True)
collection_logs = db[action_logs_collection_names]
collection_files = db[uploaded_files_collection_names]

def get_JwT_Token():
    return saved_token

def global_token(token):
    global saved_token
    saved_token = token

def send_http_request(request_type, routeURL, username, files=None, content_type=None, metadata=None, json_data=None):
    user_signature_b64 = None
    if metadata:
        metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        user_signature = sign_request(data=metadata_json, private_key=load_user_private_key(username))
        user_signature_b64 = base64.b64encode(user_signature).decode('utf-8')

    if content_type:
        if metadata:
            metadata = metadata_json # Only pass in the metadata as a json if we need to send over json without using the respective argument.
        else:
            raise ValueError("No metadata was found. Cannot proceed as the signature cannot be created without metadata. Returning")
        headers = {
            'Authorization': f'Bearer {get_JwT_Token()}',
            'X-Signature': user_signature_b64,  # Custom header for signature
            'Content-Type':  content_type
        }
    else:
        headers = {
            'Authorization': f'Bearer {get_JwT_Token()}',
            'X-Signature': user_signature_b64,  # Custom header for signature
        }
    if request_type == FlaskRequestType.POST.value:
        response = requests.post(routeURL, files=files, data=metadata, json=json_data, headers=headers, verify='cert.pem')
    elif request_type == FlaskRequestType.GET.value:
        response = requests.get(routeURL, files=files, data=metadata, json=json_data, headers=headers, verify='cert.pem')
    else:
        raise ValueError("Invalid or missing request type. Please provide a valid request type (GET or POST).")
    return response

def sign_request(private_key, data):
    """
    Sign the request data using the user's private key.

    Args:
        private_key: The RSA private key object.
        data: The data to be signed (bytes).

    Returns:
        The signature (bytes).
    """
    #print("Private Key Type:", type(private_key))  # Log the type of the public key to ensure it's an RSAPublicKey
    #print("Payload:", data)  # Log the payload being verified

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def upload_file_metadata(file_path, owner_id, original_file_extension, shared_symmetric_keys=None):
    existing_entry = collection_files.find_one({'file_path': file_path})

    if existing_entry:
        print(f'Have found an entry with find_path: {file_path}, data = {existing_entry}')
        try:
            # Get the current 'shared_with' dictionary from the existing file entry
            already_sharing_with = existing_entry.get('shared_with', {})

            # Validate that 'shared_with' is a dictionary
            if not isinstance(already_sharing_with, dict):
                raise ValueError("'shared_with' field must be a dictionary.")

            # Ensure shared_symmetric_keys is a dictionary
            if not isinstance(shared_symmetric_keys, dict):
                raise ValueError("'shared_symmetric_keys' must be a dictionary.")

            # Merge the two dictionaries
            updated_shared_with = {**already_sharing_with, **shared_symmetric_keys}

            # Attempt to update the database
            collection_files.update_one(
                {'file_path': file_path},
                {'$set': {'shared_with': updated_shared_with, 'last_updated': datetime.datetime.now().isoformat()}}
            )

        except KeyError as e:
            print(f"KeyError: Missing expected key in existing_entry or input data. Details: {str(e)}")
        except ValueError as e:
            print(f"ValueError: Invalid data provided. Details: {str(e)}")
        except Exception as e:
            print(f"UnexpectedError: An unexpected error occurred. Details: {str(e)}")
    else:
        file_size, unit = convert_size_to_bytes(os.path.getsize(file_path))
        upload_file_data = {
            'file_path': file_path,
            "original_file_extension": original_file_extension,
            'file_size': file_size,
            'size_unit': str(unit),
            'uploaded_at': datetime.datetime.now().isoformat(),
            'last_updated': datetime.datetime.now().isoformat(),
            'owner_id': owner_id,
            'shared_with': shared_symmetric_keys
        }
        collection_files.insert_one(upload_file_data)

def convert_size_to_bytes(size_in_bytes):
    """
    Convert a file size to its smallest unit (bytes) and return the unit name.
    """
    if size_in_bytes < 1024 ** 2:
        return size_in_bytes // 1024, ContentSize.KB
    elif size_in_bytes < 1024 ** 3:
        return size_in_bytes // (1024 ** 2), ContentSize.MB
    else:
        return size_in_bytes // (1024 ** 3), ContentSize.GB

def log_action(username=None, action=None, file_name=None, file_path=None):
    """Log user actions to the database."""
    log_entry = {
        "username": username,
        "action": action,
        "file_name": file_name,
        "timestamp": datetime.datetime.now().isoformat()
    }
    collection_logs.insert_one(log_entry)

class FlaskRequestType(Enum):
    POST = "post"
    GET = "get"

class FileRetrieval(Enum):
    DOWNLOAD = "download"
    SHARE = "share"

    @classmethod
    def from_value(cls, value):
        try:
            return cls(value)
        except ValueError:
            return None

class ContentSize(Enum):
    KB = 1024  # 1 KB = 1024 Bytes
    MB = 1024 * 1024  # 1 MB = 1024 KB
    GB = 1024 * 1024 * 1024  # 1 GB = 1024 MB

def convert_size(size_in_bytes, unit: ContentSize):
    return size_in_bytes / unit.value

def get_file_extension(file_path):
    """
    Retrieve the file extension from a given file path or file name.

    Args:
        file_path (str): The path or name of the file.

    Returns:
        str: The file extension (e.g., 'txt', 'jpg', 'enc'), or an empty string if no extension exists.
    """
    _, extension = os.path.splitext(file_path)
    return extension.lstrip('.')  # Remove the leading dot

# Simulate user directories
user_base_dir = "simulated_users"
os.makedirs(user_base_dir, exist_ok=True)

allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf', 'zip', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_user_private_encrypted_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private key using DPAPI
    encrypted_key = win32crypt.CryptProtectData(
        private_key_bytes,
        None,  # Description (optional)
        None,  # Optional entropy for additional security
        None,  # Reserved
        None,  # No UI prompt
        0  # Default flags
    )

    # Export public key
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_key, public_key_bytes

def get_user_directory(username):
    user_dir = os.path.join(user_base_dir, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

# Store private key for a user
def store_user_private_key(username, encrypted_key):
    user_dir = get_user_directory(username)
    key_path = os.path.join(user_dir, "private_key_protected.bin")
    with open(key_path, "wb") as key_file:
        key_file.write(encrypted_key)

# Load private key for a user
def load_user_private_key(username):
    # Step 1: Load the encrypted private key
    user_dir = get_user_directory(username)
    key_path = os.path.join(user_dir, "private_key_protected.bin")
    with open(key_path, "rb") as key_file:
        encrypted_key = key_file.read()

    # Step 2: Decrypt the private key using DPAPI
    decrypted_key = win32crypt.CryptUnprotectData(
        encrypted_key,
        None,  # Description is optional
        None,  # Optional entropy (must match the encryption step)
        None,  # Reserved
        0  # Default flags
    )[1]

    # Step 3: Load the private key object
    private_key = serialization.load_pem_private_key(
        decrypted_key,
        password=None  # No password since it was unencrypted
    )

    return private_key

def compress_file(file_path):
    compress_file_path = f"{file_path}.zip"
    with zipfile.ZipFile(compress_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, arcname=os.path.basename(file_path))
    return compress_file_path

def decompress_file(zip_file_path, output_dir=None):
    """Decompress the file (supporting zip and tar formats)."""
    file_extension = os.path.splitext(zip_file_path)[1].lower()

    if file_extension == '.zip':
        # Decompress ZIP files
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(os.path.dirname(zip_file_path))  # Extract to the same directory
        # print(f"Decompressed ZIP file: {zip_file_path}")
    elif file_extension in ['.tar', '.gz', '.bz2']:
        # Decompress TAR files (including compressed variants)
        with tarfile.open(zip_file_path, 'r:*') as tar_ref:
            tar_ref.extractall(os.path.dirname(zip_file_path))  # Extract to the same directory
        print(f"Decompressed TAR file: {zip_file_path}")
    else:
        raise ValueError(f"Unsupported file format for decompression: {file_extension}")

    # Return the path of the decompressed file(s)
    return os.path.dirname(zip_file_path)

def generate_file_hash(file_path):
    sha256_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())

    with open(file_path, 'rb') as file:
        for byte_block in iter(lambda: file.read(4096), b''):
            sha256_hash.update(byte_block)

    return sha256_hash.finalize().hex()
