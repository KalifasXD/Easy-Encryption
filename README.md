# Easy Encryption System
The Easy Encryption System is a Python-based application that provides a secure, encrypted platform for file sharing and storage. Leveraging advanced cryptographic methods and a robust user authentication system, this application ensures data integrity, confidentiality, and access control.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Features](#features)

1. I’ve only included the *.cnf* file because it allows you to generate your own SSL certificates. So, don’t worry if you don’t see any certificates in the GitHub project.
2. Update the *MONGO_URI* to point to your own MongoDB database; otherwise, any attempt to run the program will result in a database error.


## Prerequisites
Don't worry if some links are broken. Most of the prerequisites are easy to find with a simple name search on Google!
1. [Python 3.10.8](https://www.python.org/downloads/release/python-3108/).
2. A working version of [PIP](https://pypi.org/project/pip/).
3. [PyCharm Community Edition](https://www.jetbrains.com/pycharm/download/other.html)(not required, but very much recommended—it makes adding libraries to the Python project extremely easy).
   - Some familiarity with IDEs is expected.
5. [Git Bash](https://git-scm.com/downloads) terminal(used to create the SSL certificates).
6. [MongoDB](https://www.mongodb.com/products/platform/atlas-database)(You will need to create a database and three collections. I recommend using my naming for each respective collection (which are already hardcoded in the code) so you don’t have to change them yourself).
   - It’s recommended that you look up a tutorial on how to set up MongoDB and connect it with your application/website backend if you are not familiar with the process.

## Installation
1. **Install Python 3.10.8**:
   - Ensure Python 3.10.8 is installed and added to the system PATH. During installation, you should see an option to add Python to the PATH—make sure to select it.
2. **Download and Install PyCharm Community Edition**:
   - Install the latest version of PyCharm Community Edition. PyCharm is highly recommended for new users as it simplifies managing libraries and dependencies. For instance, it provides popup notifications within the editor for easy setup.
   - During installation, add the bin folder to the system PATH by selecting the corresponding option.
3. **Install Git Bash**:
   - Download and install Git Bash. Once installed, restart your computer to ensure all changes, especially to system PATH variables, are applied.
4. Clone the repository or download it:
   ```bash
   git clone https://github.com/KalifasXD/easy-encryption.git
5. Open a new powershell terminal and navigate into the project folder:
   ```bash
   cd easy-encryption
6. Create a virtual environment by pasting the quote into your previously opened powershell terminal:
   ```bash
   python -m venv venv
7. Install the dependencies:
   1. Set up the Virtual Environment:
      - Start by setting up the virtual environment, which will provide you with pip (the Python package installer).
     
   2. Activate the Virtual Environment:
      - Navigate to the **./venv/Scripts** directory in your previously opened Powershell.
      - Run the following command in PowerShell to activate the virtual environment:
         ```bash
            .\activate
         ```
      - Once activated, you should see (venv) followed by your working directory in the PowerShell prompt.
     
   3. Install Required Dependencies:
      - While inside the Scripts folder, use the following command to install the required dependencies:
         ```bash
         pip install -r path/to/the/requirements.txt
         ```
         - Replace path/to/the with the actual path to your requirements.txt file.

   4. Using PyCharm (Optional):
      - If you're working in PyCharm, it will automatically notify you about the requirements.txt file when you open the project. You can use this notification to install the dependencies directly within the editor.
        
8. You need to set up an environment variable for the secret key used in file encryption.
   #### Here’s how to create a Windows environment variable:
   1. Open the Command Prompt (CMD) as an **administrator** and type the following:
      ```bash
         setx ENCRYPTION_KEY "YourHexadecimalKey" /M
      ```
   - For the value, you need a **valid 64-character hexadecimal string**, which corresponds to a 256-bit key (32 bytes). You can use this [tool](https://www.browserling.com/tools/random-hex) to generate the required string. Just ensure you change the length from 32 to 64 before generating the key. Be sure to enclose the generated string within the quotation marks **("")**.
     
   - Example of successfully creating an encryption key(make sure to remove any not required spaces:
     ```bash
        setx ENCRYPTION_KEY "cc212408572d1dccecfa07892b96b7e49741b810de13078a89dacaf852612f96" /M
     ```
- Ensure that the current directory in Git Bash is your project directory before proceeding. Otherwise, you'll need to manually move all the generated files into your project folder.
9. Generate the SSL Certificates:
   1. **Boot up Git Bash**:
      - By default, Git Bash includes the ability to create SSL certificates.
      - Run the following command to generate them:
     

         **1. Generate a Private Key:**
           ```bash
           openssl genrsa -out private.key 2048
           ```
         **2. Create a Certificate Signing Request (CSR):**
         ```bash
         openssl req -new -key private.key -out cert.csr -config openssl.cnf
         ```
         **3. Generate the Self-Signed Certificate:**
         ```bash
         openssl x509 -req -days 365 -in cert.csr -signkey private.key -out cert.pem -extensions v3_req -extfile openssl.cnf
         ```
         **4. Combine Private Key and Certificate Into key.pem:**
         ```bash
         cat private.key cert.pem > key.pem
         ```
        - Keep in mind that the .cnf file specifies the **Common Name (CN)** for handling requests, defaulting to *CN = 127.0.0.1*, the local address for ***HTTPS***. If your server listens on a **different** local address, you must ***regenerate the SSL certificates***, setting the CN in the .cnf file to match your server's listening address.
     2. **As a last step, we need to add the cert.pem into the MMC(Microsoft Management Console):**
           1. Press **Win + R**, type **mmc**, and press Enter.
           2. Add the Certificates Snap-in:
              1. Go to File → **Add/Remove Snap-in**.
              2. Select Certificates, click Add.
              3. Choose Computer Account → Next → Finish.
           3. Navigate to **Trusted Root Certification Authorities**:
              1. Expand the tree under **Certificates**.
           4. Import the *cert.pem* File:
                 1. Right-click Certificates → All Tasks → Import.
                 2. Select your *cert.pem* file
                    - If the *cert.pem* file is not visible, set the file type to **All Files**.
                 3. Follow the prompts to add it.
           5. Save & Close.

## Getting Started

1. First and foremost, you will need to launch the server script(Server_Launch.py). So bring up a brand new Powershell terminal.
   
2. Navigate to the project folder (where the clone was downloaded).

3. While inside the project folder, navigate to.
   ```bash
   cd venv/scripts
4. Now, call ./activate to enable the Virtual Environment.
   ```bash
   ./activate
5. Now navigate back to the folder you accessed in step 2.
   ```bash
   cd ../..
   ```
   - *The above command should get to the same position as you were in the second step.*

7. Run the following command to start the Flask server
   ```bash
   python Server_Launch.py
   
8. If you have completed every step successfully, it should look like this:
![server_running](assets/server_running.jpg)

That’s it! You should now get a message saying the Flask server is up and running.
This script is responsible for holding all of the server logic. It is what "listens" for requests and acts accordingly. If you make any changes to the script, remember to re-run it before testing your changes.

- Assuming the server has been successfully initialized, the most challenging part of the setup process should now be complete.

#### All you got now left is to configure the client

1. Open the project in an Integrated Development Environment (IDE), preferably **PyCharm**.
   - Purpose of ***main.py***:
      - Acts as the client-side of the application.
      - Serves as the entry point for interacting with the program.
   - **Setup Instructions**:
      - Open the project in the PyCharm Editor.
      - Connect your own MongoDB database to the program before running it.
   - **Explanation of the Client-Side**:
      - Refers to the part of the application that users interact with directly.
      - Includes the user interface and handles user requests.
      - Facilitates communication with the server to send or retrieve data.

3. Configure the MongoDB settings to connect to your specific database instance.
   1. Refer to the official MongoDB documentation page for detailed instructions on creating and connecting a MongoDB database to a Python script: [MongoDB Documentation](https://www.mongodb.com/docs/atlas/atlas-ui/databases/).
   2. By default, you are only required to:
      - Create the database(Ensure the database name is updated within the **Config.py** file. The variable to modify is **database_name**).
      - Update the query string located in the Config.py file by replacing the provided credentials with your own.
   3. The **collections** are dynamically created when an element is added to them if they do not already exist.
   4. To modify collection names:
      - Navigate to the Config.py file.
      - Replace the existing collection names with names of your choice.
   5. The query string mentioned in Step 2(**One of the two modifications required to establish a connection with the database**).
      ```bash
         MONGO_URI = "mongodb+srv://vasilis944:qEmWxlrXh2Hlssf1@cluster0.z56q5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
      ```
      - Update the Query String:
         - MongoDB will provide you with a unique query string for connecting to your database.
         - Replace the existing query string in the code with the one you receive.
         - Ensure you include your database user credentials (username and password) in the provided query string for a successful connection.
       
4. This completes all the necessary configuration. You can now execute the Python script (by clicking the green arrow in the top-right corner of your IDE or the respective execution button of the IDE you chose) and proceed to register a new user to get started.
5. To register a new user:
   1. Enter the desired username and password in their respective fields.
   2. Click the **Register** button.
   3. A confirmation message will indicate successful account creation.
  
## Features
1. User Authentication
   - Users can register and log in using unique credentials.
   - User passwords are hashed for secure storage.
   - Public and private keys are generated for each user during registration.
   
2. File Upload
   - Files are encrypted using AES before upload.
   - Metadata, including file size, original file extension, and a SHA-256 hash, is stored securely.
   - File uploads are validated against a maximum size limit (500 MB).
     
3. File Sharing
   - Owners can share files with other users by encrypting symmetric keys with the recipient's public key.
   - Shared files' access details are updated in a MongoDB database.
     
4. File Download
   - Users can download files they own or that have been shared with them.
   - Files are decrypted locally after download, restoring their original format.

5. User Management
   - Retrieve a list of all usernames for sharing purposes.
   - Revoke access for users previously shared files.
     
6. File Management
   - Compress files before upload and decompress them after download.
   - Support for deleting files and their associated metadata.

7. Security
   - JWT-based token authentication for secure API access.
   - RSA encryption for sharing symmetric keys.
   - AES encryption for file contents with additional validation using SHA-256 hashes.
   - Encrypted private keys stored locally using DPAPI (Windows).
     
8. Error Handling
   - Handles scenarios like invalid tokens, missing data, large files, and tampered files with detailed error responses.

### System Architecture
![architecture](assets/System_Architecture.jpg)
![architecture2](assets/System_Architecture_2.png)

### User Workflow
![workflow](assets/User_Workflow.png)

### Dependencies and Libraries
   - Cryptography: RSA and AES encryption.
   - Tkinter: GUI for user interaction.
   - PyMongo: MongoDB integration.
   - Flask: API backend.
   - Werkzeug: File handling utilities.
   - Requests: HTTP requests for API calls.
   - OS & Pathlib: File system operations.
