# SSHoney
# SSHoney - Simple SSH Honeypot

`SSHoney.py` is a simple SSH honeypot server written in Python. Its primary purpose is to listen for incoming SSH connections, capture attempted authentication credentials (username/password and public key attempts), and log them to standard output and optionally to a file. It rejects all authentication attempts, preventing actual login.

## Features

*   Listens on a configurable IP address and port.
*   Logs attempted usernames and passwords in cleartext.
*   Logs attempted public key authentications (username, key type, fingerprint).
*   Outputs logs to standard output (stdout).
*   Optionally logs to a specified file.
*   Handles multiple connections concurrently using threading.
*   Masquerades as a standard OpenSSH server (`SSH-2.0-OpenSSH_8.2p1`).
*   Handles common disconnection scenarios gracefully (e.g., banner scanning).

## Requirements

*   Python 3.x
*   `paramiko` library

## Installation

1.  **Clone the repository or download the script:**
    ```bash
    # If using git
    # git clone <repository_url>
    # cd <repository_directory>
    ```
2.  **Install the required library:**
    ```bash
    pip install paramiko
    ```

## Usage

Run the script from your terminal. You might need `sudo` or administrator privileges if you want to bind to privileged ports like port 22.

**Basic usage (listens on 0.0.0.0:22, logs to stdout only):**

```bash
sudo python SSHoney.py
```

**Listen on a different port (e.g., 2222) and log to stdout:**

```bash
python SSHoney.py --port 2222
```

**Listen on port 2222 and log to both stdout and a file (`credentials.log`):**

```bash
python SSHoney.py --port 2222 --log-file credentials.log
```

**Specify a specific host IP (e.g., 192.168.1.100):**

```bash
python SSHoney.py --host 192.168.1.100 --port 2222
```

**Help:**

```bash
python SSHoney.py --help
```

## Logging Output

Logs will show connection attempts, successful/failed banner exchanges, authentication attempts (including credentials), and disconnections. Example log entry for a password attempt:

```
2023-10-27 10:30:15,123 - INFO - Authentication attempt: 192.168.1.5:54321 tried username: 'root' with password: 'password123'
```

## ⚠️ Disclaimer

This tool is intended for security research, testing, and educational purposes **only**. Running a honeypot may have legal and ethical implications depending on your jurisdiction and how you use it. Ensure you have proper authorization before deploying this tool on any network. The authors are not responsible for any misuse or damage caused by this script. 
