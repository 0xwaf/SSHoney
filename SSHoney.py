#!/usr/bin/env python3
# SSHoney.py - A simple SSH honeypot server to capture authentication credentials

import socket
import threading
import paramiko
import logging
import sys
import signal
import argparse
import os
from datetime import datetime

# ANSI Color Codes for logging
COLOR_RESET = '\033[0m'
COLOR_GREEN = '\033[92m'  # Success
COLOR_YELLOW = '\033[93m' # Warning
COLOR_RED = '\033[91m'    # Error
COLOR_BLUE = '\033[94m'   # Info

# Configuration
DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 22
DEFAULT_LOG_FILE = None  # Set to None to disable file logging

# Define custom log level for credential capture
AUTH_SUCCESS = 25  # Between INFO (20) and WARNING (30)

# Add custom log level name to logging
logging.addLevelName(AUTH_SUCCESS, 'AUTH_SUCCESS')

# Add auth_success method to Logger class
def auth_success(self, message, *args, **kwargs):
    """Log credential capture at AUTH_SUCCESS level (25)"""
    self.log(AUTH_SUCCESS, message, *args, **kwargs)

# Add the method to the Logger class
logging.Logger.auth_success = auth_success

class ColorFormatter(logging.Formatter):
    """Custom formatter that adds color to log records based on level"""
    
    def __init__(self, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt, datefmt, style)
        self.colors = {
            logging.DEBUG: '',  # No color
            logging.INFO: COLOR_BLUE,
            AUTH_SUCCESS: COLOR_GREEN,
            logging.WARNING: COLOR_YELLOW,
            logging.ERROR: COLOR_RED,
            logging.CRITICAL: COLOR_RED
        }
    
    def format(self, record):
        # Store original
        orig_levelname = record.levelname
        
        # Add color if outputting to a terminal
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            color = self.colors.get(record.levelno, '')
            if color:
                record.levelname = f"{color}{record.levelname}{COLOR_RESET}"
                # Colorize the message too for better visibility
                if record.levelno == AUTH_SUCCESS:
                    message = super().format(record)
                    return f"{COLOR_GREEN}{message}{COLOR_RESET}"
        
        # Call the original formatter
        message = super().format(record)
        
        # Restore the original level name (in case the formatter is shared)
        record.levelname = orig_levelname
        
        return message

class PlainFormatter(logging.Formatter):
    """Standard formatter for log files (no color codes)"""
    pass

class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self, logger, client_address):
        self.logger = logger
        self.client_address = client_address

    def check_auth_password(self, username, password):
        """
        Log the username and password, then reject the authentication
        """
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        log_message = f"Credentials captured: User='{username}' Pass='{password}' from {client_ip}:{client_port}"
        # Use auth_success for credential capture
        self.logger.auth_success(log_message)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        """
        Allow a session channel to be opened
        """
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        """
        Log publickey authentication attempts and reject
        """
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        key_type = key.get_name()
        key_fingerprint = key.get_fingerprint().hex()
        log_message = f"Public key auth attempt: User='{username}' KeyType='{key_type}' (fingerprint: {key_fingerprint}) from {client_ip}:{client_port}"
        # Use auth_success level for publickey captures as well
        self.logger.auth_success(log_message)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        """
        Allow password and publickey authentication methods
        """
        return 'password,publickey'

def setup_logging(log_file=None):
    """
    Set up logging with colored output for terminal and optional file logging
    """
    # Create logger
    logger = logging.getLogger('SSHoney')
    logger.setLevel(logging.INFO)
    
    # Clear any existing handlers (important for tests/restarts)
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)
    
    # Create formatters
    console_format = '%(asctime)s - %(levelname)s - %(message)s'
    file_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    color_formatter = ColorFormatter(console_format)
    plain_formatter = PlainFormatter(file_format)

    # Create stdout handler with color formatter
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(color_formatter)
    logger.addHandler(stdout_handler)

    # Create file handler with plain formatter if log_file is specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(plain_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up file logging: {e}")

    # Attempt to suppress Paramiko's internal tracebacks
    paramiko_logger = logging.getLogger('paramiko')
    paramiko_logger.setLevel(logging.CRITICAL)  # Only show critical errors
    paramiko_logger.addHandler(logging.NullHandler())  # Prevent propagation
    
    # Also suppress related loggers that might show errors
    logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)
    
    return logger

def handle_client(client_socket, client_address, host_key, logger):
    """
    Handle an incoming client connection
    """
    try:
        # Create a Transport for this connection
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1"  # Masquerade as OpenSSH

        # Start the server with enhanced exception handling
        server = SSHHoneypotServer(logger, client_address)
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, ConnectionResetError, socket.error) as e:
            # Log based on exception type or message
            if isinstance(e, paramiko.SSHException) and "Error reading SSH protocol banner" in str(e):
                logger.warning(f"Client {client_address[0]}:{client_address[1]} disconnected during banner exchange")
            elif isinstance(e, EOFError):
                logger.warning(f"Client {client_address[0]}:{client_address[1]} disconnected unexpectedly (EOFError)")
            elif isinstance(e, ConnectionResetError):
                logger.warning(f"Client {client_address[0]}:{client_address[1]} reset the connection")
            elif isinstance(e, socket.error):
                logger.warning(f"Socket error with {client_address[0]}:{client_address[1]}: {e}")
            else:
                logger.error(f"SSH negotiation error with {client_address[0]}:{client_address[1]}: {e}")
            return

        # Wait for authentication with improved error handling
        try:
            channel = transport.accept(30)
            if channel is None:
                logger.info(f"No channel established with {client_address[0]}:{client_address[1]}")
            elif channel:
                channel.close()
        except (paramiko.SSHException, EOFError, socket.error) as e:
            logger.warning(f"Channel negotiation failed with {client_address[0]}:{client_address[1]}: {e}")

    except Exception as e:
        logger.error(f"Unexpected error handling client {client_address[0]}:{client_address[1]}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass
        logger.info(f"Connection closed with {client_address[0]}:{client_address[1]}")

def main(host=DEFAULT_HOST, port=DEFAULT_PORT, log_file=DEFAULT_LOG_FILE):
    """
    Main function to set up and run the SSH honeypot server
    """
    # Set up logging
    logger = setup_logging(log_file)
    logger.info(f"Starting SSHoney on {host}:{port}")

    # Generate server key
    host_key = paramiko.RSAKey.generate(2048)
    logger.info("Generated RSA key for the server")

    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Bind and listen
        server_socket.bind((host, port))
        server_socket.listen(5)
        logger.info(f"Listening for connections on {host}:{port}")

        # Set up signal handling for graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutting down SSH honeypot server...")
            server_socket.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        
        # Main loop
        while True:
            client_socket, client_address = server_socket.accept()
            logger.info(f"Connection from {client_address[0]}:{client_address[1]}")
            
            # Handle client in a new thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, host_key, logger)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except Exception as e:
        logger.error(f"Error in main server loop: {e}")
    finally:
        server_socket.close()
        logger.info("Server socket closed")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='SSH Honeypot Server')
    parser.add_argument('--host', type=str, default=DEFAULT_HOST,
                        help=f'Host IP to listen on (default: {DEFAULT_HOST})')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--log-file', type=str, default=DEFAULT_LOG_FILE,
                        help='Log file path (default: log to stdout only)')
    
    args = parser.parse_args()
    
    # Run the server
    main(args.host, args.port, args.log_file) 
