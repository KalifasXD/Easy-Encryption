# Easy Encryption System
The Easy Encryption System is a Python-based application that provides a secure, encrypted platform for file sharing and storage. Leveraging advanced cryptographic methods and a robust user authentication system, this application ensures data integrity, confidentiality, and access control.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)


## Prerequisites
Do not be afraid if links are broken. Most of the prerequisites are easy to find with just a simple name search on Google!
1. Python 3.10+
2. A working version of [PIP](https://pypi.org/project/pip/)
3. [PyCharm](https://www.jetbrains.com/pycharm/download/?section=windows)(not actually required but very much recommended. It makes adding libraries to the python project, extremely easy)
4. Git Bash terminal(will be used to create the SSL certificates)
5. 

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/KalifasXD/easy-encryption.git
2. Navigate into the project folder:
   ```bash
   cd easy-encryption
3. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
4. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   (If you have PyCharm, PyCharm will let you know that you can use this file to install the required dependencies once you have booted up the project!

## Usage

1. First and foremost, you will need to launch the server script(Server_Launch.py).
   ```bash
   Open powershell/terminal
   
2. Navigate the project folder(where the clone was downloaded).

3. While inside of the project file navigate to.
   ```bash
   cd ../venv/scripts
4. Now call ./activate to enable the flask server.
   ```bash
   ./activate
5. Now navigate back to where you navigated on the 2nd step.

6. Run the following command to start the flask server python main.py
It should look something like this
![server_running](assets/server_running.jpg)

That’s it. You should now get a message saying the flask server is up and running.
This script is responsible for holding all of the server logic. It is what "listens" for requests and acts accordingly. Obviously, if you edit the script, make sure to re-run it before testing out the changes you made.
