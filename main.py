from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os, tkinter as tk, requests, mimetypes
from tkinter import ttk, filedialog, messagebox
import base64, json
from config import (MAX_CONTENT_LENGTH, convert_size, ContentSize, UPLOAD_FOLDER, generate_user_private_encrypted_key, \
                    store_user_private_key, load_user_private_key, compress_file, decompress_file, generate_file_hash,
                    SECRET_KEY, FlaskRequestType, \
                    collection_users, collection_files, FileRetrieval, log_action, get_file_extension, global_token,
                    send_http_request)
import config
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64decode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Constants for encryption
BLOCK_SIZE = 16
KEY_SIZE = 32

BASE_URL = "https://127.0.0.1:443"  # Replace with your Flask server URL
LOGIN_URL = f"{BASE_URL}/login"
REGISTER_URL = f"{BASE_URL}/register"
UPLOAD_URL = f"{BASE_URL}/upload"
DOWNLOAD_URL = f"{BASE_URL}/download"
RETRIEVE_FILES_URL = f"{BASE_URL}/files"
FILE_SHARE_URL = f"{BASE_URL}/share_file"
RETRIEVE_ALL_USERNAMES_URL = f"{BASE_URL}/retrieve_all_usernames"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Utility: Load the encryption key from the environment
def load_encryption_key():
    encryption_key_hex = SECRET_KEY
    if not encryption_key_hex:
        raise ValueError("Encryption key not set in environment variables.")
    if len(encryption_key_hex) != 64:
        raise ValueError("Invalid key length. Hex key must be 64 characters.")
    return bytes.fromhex(encryption_key_hex)


# AES Encryption function
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    cipher_text = cipher.encrypt(pad(plaintext, BLOCK_SIZE))

    # Extract the original file extension and store it as bytes
    original_extension = os.path.splitext(file_path)[1]
    original_extension_bytes = original_extension.encode('utf-8')  # Convert extension to bytes
    extension_length = len(original_extension_bytes)
    extension_length_bytes = extension_length.to_bytes(1, 'big')  # Store length in 1 byte

    # Combine metadata (extension length + extension), IV, and ciphertext
    encrypted_content = extension_length_bytes + original_extension_bytes + iv + cipher_text

    # Save the encrypted file with a `.enc` extension
    base_name = os.path.basename(file_path)  # Get the filename only
    encrypted_filepath = file_path
    with open(encrypted_filepath, 'wb') as f:
        f.write(encrypted_content)

    print(f"File Encrypted: {encrypted_filepath}")
    return encrypted_filepath


# AES Decryption function
def decrypt_file(encrypted_file_path, key, save_directory):
    # Make sure the save directory has a correct path format

    with open(encrypted_file_path, 'rb') as f:
        file_content = f.read()

    # Extract metadata: extension length and extension
    extension_length = file_content[0]  # Read the first byte for the length
    original_extension_bytes = file_content[1:1 + extension_length]
    original_extension = original_extension_bytes.decode('utf-8')  # Decode extension from bytes
    iv = file_content[1 + extension_length:1 + extension_length + BLOCK_SIZE]
    ciphertext = file_content[1 + extension_length + BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    # Construct the decrypted file path, restoring the original extension
    original_filename = os.path.splitext(os.path.basename(encrypted_file_path))[0]  # Remove `.enc`
    decrypted_file_path = os.path.join(os.path.normpath(save_directory), original_filename + original_extension)

    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_file_path

def login_or_register():
    """Login or Register screen."""
    root = tk.Tk()
    root.title("Login or Register")

    tk.Label(root, text="Username:").pack(pady=5)
    username_entry = tk.Entry(root)
    username_entry.pack(pady=5)

    tk.Label(root, text="Password:").pack(pady=5)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=5)

    def handle_login():
        """Handle user login."""
        username = username_entry.get()
        password = password_entry.get()

        response = send_http_request(
            request_type=FlaskRequestType.POST.value,
            routeURL=LOGIN_URL,
            json_data={"username": username, "password": password},
            username=username
        )
        # If the response status code is not 200, handle the error
        if response.status_code == 200:
            try:
                files = response.json()
            except ValueError:
                print("Error: Response is not a valid JSON.")
        else:
            print(f"Request failed with status code {response.status_code}")
        if response.status_code == 200:
            messagebox.showinfo("Login Successful", "Welcome!")
            response_data = response.json()
            token = response_data.get("token")  # Extract token from response
            global_token(token)
            root.destroy()
            private_key = load_user_private_key(username)
            show_menu(username)  # Pass username to the menu
        else:
            messagebox.showerror("Login Failed", response.json().get("message", "Unknown error"))

    def handle_register():
        """Handle user registration."""
        username = username_entry.get()
        password = password_entry.get()
        private_encrypted_key, public_key_bytes = generate_user_private_encrypted_key()
        public_key_base64 = base64.b64encode(public_key_bytes).decode('utf-8')
        data = {"username": username, "password": password, "public_key": public_key_base64}
        response = send_http_request(
            request_type=FlaskRequestType.POST.value,
            routeURL=REGISTER_URL,
            json_data=data,
            username=username
        )

        if response.status_code == 201:
            store_user_private_key(username, encrypted_key=private_encrypted_key)
            messagebox.showinfo("Registration Successful", "You can now log in.")
        elif response.status_code == 409:
            messagebox.showerror("Registration Failed", "User already exists!")
        else:
            messagebox.showerror("Registration Failed", response.json().get("message", "Unknown error"))

    tk.Button(root, text="Login", command=handle_login).pack(pady=5)
    tk.Button(root, text="Register", command=handle_register).pack(pady=5)

    root.mainloop()


def show_menu(username):
    """Display the main menu for the user."""
    menu_window = tk.Tk()
    menu_window.title("Main Menu")

    tk.Label(menu_window, text=f"Welcome, {username}!").pack(pady=10)

    def handle_encrypt_and_upload():
        try:
            """Encrypt a file and upload it to the server."""
            file_path = filedialog.askopenfilename(title="Select File to Upload")
            if not file_path:
                messagebox.showerror("Error", "No file selected.")
                return

            file_size = os.path.getsize(file_path)
            file_size_mb = convert_size(file_size, ContentSize.MB)  # Size in MB

            if file_size_mb > convert_size(MAX_CONTENT_LENGTH, ContentSize.MB):
                root = tk.Tk()
                root.withdraw()  # Hide the root window
                messagebox.showerror("Error",
                                     f"File is too large. The maximum allowed size is {convert_size(MAX_CONTENT_LENGTH, ContentSize.MB)}  MB")
                root.destroy()
                return

            mime_type, _ = mimetypes.guess_type(file_path)
            original_file_extension = get_file_extension(file_path)
            mime_type = mime_type or 'application/octet-stream'  # Default MimeType if nothing else is found
            compressed_file_path = compress_file(file_path)
            encrypted_file_path = encrypt_file(compressed_file_path, load_encryption_key())
            hashed_file = generate_file_hash(encrypted_file_path)

            metadata = {
                'username': username,
                'file_size': str(file_size), # Always convert data types to strings as JSON automatically does it on server causing a mismatch and the signing verification to fail
                'hashed_file': hashed_file,
                'original_file_extension': original_file_extension
            }

            with open(encrypted_file_path, 'rb') as file:
                files = {'file': (file.name, file, mime_type)}  # Do not include the file itself because speed is important and large files can cause the "signing" to be slow
                response = send_http_request(
                    request_type=FlaskRequestType.POST.value,
                    routeURL=UPLOAD_URL,
                    metadata=metadata,
                    username=username,
                    files=files
                )

            response_data = response.json()
            messagebox.showinfo("File Uploaded", f"Uploaded file saved: {response_data.get('server_stored_path')}")
            # remove the compressed file
            os.remove(encrypted_file_path)
        except FileNotFoundError:
            print(f"File not found: {encrypted_file_path}")
        except requests.RequestException as e:
            print(f"An error occurred during file upload: {e}")



    def handle_decrypt_and_download():
        """Decrypt a file downloaded from the server."""
        data = {
            'request-type': FileRetrieval.DOWNLOAD.value
        }
        response = send_http_request(
            request_type=FlaskRequestType.GET.value,
            routeURL=RETRIEVE_FILES_URL,
            metadata=data,
            username=username
        )
        files = response.json()

        def select_file():
            selected_file = listbox.get(listbox.curselection())
            dialog.destroy()
            download_and_decrypt(selected_file)

        dialog = tk.Tk()
        dialog.title("Select File to Download")

        tk.Label(dialog, text="Available Files:").pack(pady=5)
        listbox = tk.Listbox(dialog, selectmode=tk.SINGLE, width=50, height=15)
        for file in files:
            listbox.insert(tk.END, file)
        listbox.pack(pady=5)

        tk.Button(dialog, text="Download", command=select_file).pack(pady=5)
        dialog.mainloop()

    def download_and_decrypt(filename):
        """Download the selected file and decrypt it."""
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            messagebox.showerror("Error", "No output directory selected.")
            return

        try:
            # Create data for both the request and the signing
            metadata = {
                'username': username
            }

            response = send_http_request(
                request_type=FlaskRequestType.GET.value,
                routeURL=f"{DOWNLOAD_URL}/{filename}",
                metadata=metadata,
                username=username
            )
            if response.status_code == 200:
                #with open(filename, 'wb') as f:
                    # f.write(response.content)  # Save the file

                file_path = os.path.join(UPLOAD_FOLDER, filename)
                log_action(username, "Download", filename, file_path)
                # Step 4: Decrypt the downloaded file

                file_metadata = collection_files.find_one({'file_path': file_path})
                if file_metadata:
                    if file_metadata.get('owner_id') == username:
                        encryption_key = load_encryption_key()  # Load the key from environment variables
                        decrypted_file_path = decrypt_file(file_path, encryption_key, output_dir)
                    else:
                        user_specific_symmetric_key = file_metadata.get('shared_with').get(username)
                        #encryption_key = get_random_bytes(32)
                        symmetric_key_decoded = base64.b64decode(user_specific_symmetric_key)
                        encryption_key = decrypt_with_private_key(username, symmetric_key_decoded)
                        decrypted_file_path = decrypt_file(file_path, encryption_key, output_dir)

                # Step 5: Decompress the file once it has been decrypted
                decompress_file(decrypted_file_path)
                os.remove(decrypted_file_path)

                # Step 6: Notify the user of success
                messagebox.showinfo("Success", f"File decrypted and saved at: {decrypted_file_path}")
            else:
                print(f"Failed to download file. Status Code: {response.status_code}")
                print(response.text)  # This will show the error message or non-JSON response.
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    def handle_file_sharing():

        def share_files(listbox, dialog):
            def share_with_users(listbox_users, dialog_users):
                selected_user_indices = listbox_users.curselection()
                selected_users = [listbox_users.get(i) for i in selected_user_indices]
                dialog_users.destroy()
                encrypted_symmetric_keys = {}
                for file in selected_files:
                    encrypted_symmetric_keys.clear()
                    for user in selected_users:

                        # Determine whether user already has access to the file
                        #if file_user_access:
                        try:
                            # Fetch the public key and encrypt the symmetric key
                            public_key_pem = get_user_public_key(user)
                            encrypted_key = encrypt_with_public_key(public_key_pem, load_encryption_key())

                            # Add the encrypted key to the list but first convert it to string from byte
                            encrypted_symmetric_keys[user] = (base64.b64encode(encrypted_key).decode('utf-8'))
                        except Exception as e:
                            print(f"Error encrypting key for user {user}: {e}")

                    metadata = {
                        'selected_usernames': selected_users,
                        'encrypted_symmetric_keys': encrypted_symmetric_keys,
                        'file_path': file
                    }

                    share_file_response = send_http_request(
                        request_type=FlaskRequestType.POST.value,
                        routeURL=FILE_SHARE_URL,
                        metadata=metadata,
                        username=username,
                        content_type='application/json'
                    )
                    if 200 <= share_file_response.status_code < 300:
                        messagebox.showinfo("File Sharing Successful", share_file_response.json().get('message'))
                    else:
                        messagebox.showerror("File Sharing Failed", share_file_response.json().get("error"))

            selected_indices = listbox.curselection()
            selected_files = [listbox.get(i) for i in selected_indices]
            dialog.destroy()
            response_get_all_usernames = send_http_request(
                request_type=FlaskRequestType.POST.value,
                routeURL=RETRIEVE_ALL_USERNAMES_URL,
                username=username
            )
            users = set() # Initiate the users list
            # If a user already has access to the file exclude them from the share list or if the user is the owner
            for file in selected_files:
                users.clear()
                file_metadata = collection_files.find_one({'file_path': os.path.join(UPLOAD_FOLDER, file)})
                if not file_metadata:
                    messagebox.showerror("Error", f"Can't find metadata for file: {os.path.join(UPLOAD_FOLDER, file)}")
                    continue
                file_user_access = file_metadata.get('shared_with', {})
                usernames = file_user_access.keys()
                print(f'Users who have access to the file: {usernames}')
                for user in response_get_all_usernames.json():
                    if user != username and user not in usernames: # Do not add the owner to the share with list
                        users.add(user)

            Create_Dialog_Window(title_dialog="Select Users to Share", label_text="Available Users:",
                                 button_text="Share with Users", data_list=users, callback_function=share_with_users)

        data = {
            'request-type': FileRetrieval.SHARE.value
        }
        response = send_http_request(
            request_type=FlaskRequestType.GET.value,
            routeURL=RETRIEVE_FILES_URL,
            metadata=data,
            username=username
        )
        files = response.json()
        Create_Dialog_Window("Select Files to Share", "Available Files:", "Select Files", files, share_files)

    def handle_revoke_file_access():
        def select_users_file_access(listbox_revoke, dialog_revoke):
            def remove_file_access(listbox_remove, dialog_remove):
                selected_user_indices = listbox_remove.curselection()
                selected_users = [listbox_remove.get(i) for i in selected_user_indices]
                dialog_remove.destroy()
                for file in selected_files:
                    file_metadata = collection_files.find_one({'file_path': os.path.join(UPLOAD_FOLDER, file)})
                    if not file_metadata:
                        messagebox.showerror("Error", f"Can't find metadata for file: {os.path.join(UPLOAD_FOLDER, file)}")
                        continue

                    # Get the current shared_with users
                    users_with_file_access = file_metadata.get('shared_with', {})
                    successful_revoke = []
                    failed_revoke = []

                    for user in list(users_with_file_access.keys()):  # Iterate through current users with access
                        if user in selected_users:  # Check if user has lost access
                            # Remove the user from the shared_with dictionary
                            result = collection_files.update_one(
                                {'file_path': os.path.join(UPLOAD_FOLDER, file)},
                                {'$unset': {f'shared_with.{user}': ""}}
                            )
                            if result.modified_count > 0:
                                successful_revoke.append(user)
                            else:
                                failed_revoke.append(user)

                    # Display messages for successful and failed revocations
                    if successful_revoke:
                        messagebox.showinfo(
                            "Success",
                            f"Successfully revoked access for the following users on file '{file}':\n" +
                            "\n".join(successful_revoke)
                        )
                    if failed_revoke:
                        messagebox.showerror(
                            "Failure",
                            f"Failed to revoke access for the following users on file '{file}':\n" +
                            "\n".join(failed_revoke)
                        )

            selected_indices = listbox_revoke.curselection()
            selected_files = [listbox_revoke.get(i) for i in selected_indices]
            dialog_revoke.destroy()
            users_with_access = set()
            for file in selected_files:
                users_with_access.clear()
                file_metadata = collection_files.find_one({'file_path': os.path.join(UPLOAD_FOLDER, file)})
                if not file_metadata:
                    messagebox.showerror("Error", f"Can't find metadata for file: {os.path.join(UPLOAD_FOLDER, file)}")
                    continue
                file_user_access = file_metadata.get('shared_with', {})
                users_with_access = file_user_access.keys()

            Create_Dialog_Window(title_dialog="Select Users to Revoke Access", label_text="Available Users:",
                                 button_text="Revoke Access", data_list=users_with_access, callback_function=remove_file_access)

        # Retrieve the list of users who have access to the file
        data = {
            'request-type': FileRetrieval.SHARE.value
        }
        response = send_http_request(
            request_type=FlaskRequestType.GET.value,
            routeURL=RETRIEVE_FILES_URL,
            metadata=data,
            username=username
        )
        if response.status_code != 200:
            messagebox.showerror("Error", "Failed to retrieve files.")
            return
        retrieved_files = response.json()
        Create_Dialog_Window(title_dialog="Select Files to Revoke Access", label_text="Available Files:",
                             button_text="Revoke Access", data_list=retrieved_files, callback_function=select_users_file_access)

    def handle_file_deletion():
        def file_deletion(listbox_delete, dialog_delete):
            selected_indices = listbox_delete.curselection()
            selected_files = [listbox_delete.get(i) for i in selected_indices]
            dialog_delete.destroy()
            for file in selected_files:
                file_metadata = collection_files.find_one({'file_path': os.path.join(UPLOAD_FOLDER, file)})
                if not file_metadata:
                    messagebox.showwarning("File Not Found", f"No metadata found for file: {file}")
                    continue
                # Remove the file's metadata from the database
                delete_result = collection_files.delete_one({'file_path': os.path.join(UPLOAD_FOLDER, file)})

                if delete_result.deleted_count > 0:
                    os.remove(os.path.join(UPLOAD_FOLDER,file))
                    # File metadata was successfully deleted
                    messagebox.showinfo("File Deleted",
                                        f"Metadata and file for file '{file}' has been successfully deleted.")
                else:
                    # File metadata deletion failed
                    messagebox.showerror("Deletion Failed", f"Failed to delete metadata for file '{file}'.")

        # Retrieve the list of files the user can share-Meaning he is the owner of them
        data = {
            'request-type': FileRetrieval.SHARE.value
        }
        response = send_http_request(
            request_type=FlaskRequestType.GET.value,
            routeURL=RETRIEVE_FILES_URL,
            metadata=data,
            username=username
        )
        if response.status_code != 200:
            messagebox.showerror("Error", "Failed to retrieve files.")
            return
        Create_Dialog_Window(title_dialog="Select Files to Delete", label_text="Available Files:",
                             button_text="Delete Files", data_list=response.json(),
                             callback_function=file_deletion)
    tk.Button(menu_window, text="Upload File", command=handle_encrypt_and_upload).pack(pady=10)
    tk.Button(menu_window, text="Delete Files", command=handle_file_deletion).pack(pady=10)
    tk.Button(menu_window, text="Download File", command=handle_decrypt_and_download).pack(pady=10)
    tk.Button(menu_window, text="Share Files", command=handle_file_sharing).pack(pady=10)
    tk.Button(menu_window, text="Revoke File Access", command=handle_revoke_file_access).pack(pady=10)
    tk.Button(menu_window, text="Logout", command=menu_window.destroy).pack(pady=10)

    menu_window.mainloop()


def Create_Dialog_Window(title_dialog, label_text, button_text, data_list, callback_function):
    dialog = tk.Tk()
    dialog.title(title_dialog)

    tk.Label(dialog, text=label_text).pack(pady=5)
    listbox = tk.Listbox(dialog, selectmode=tk.MULTIPLE, width=50, height=15)
    for list_element in data_list:
        listbox.insert(tk.END, list_element)
    listbox.pack(pady=5)

    tk.Button(dialog, text=button_text, command=lambda: callback_function(listbox, dialog)).pack(pady=5)
    dialog.mainloop()

# Function to encrypt data using a public key
def encrypt_with_public_key(public_key_pem, data):
    # Ensure the public key is in the right format
    if isinstance(public_key_pem, RSAPublicKey):
        public_key = public_key_pem  # Already a public key object, no need to deserialize
    else:
        public_key = serialization.load_pem_public_key(public_key_pem)

    # Encrypt the data
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Function to decrypt data using a private key
def decrypt_with_private_key(username, encrypted_data):
    private_key = load_user_private_key(username)

    # Ensure the encrypted data is in bytes format
    # if isinstance(encrypted_data, str):
    #     encrypted_data = b64decode(encrypted_data)

    try:
        # Decrypt the data
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

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

if __name__ == '__main__':
    login_or_register()

