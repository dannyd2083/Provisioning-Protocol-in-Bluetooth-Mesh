#!/usr/bin/env python3
import logging
import random
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from toolbox import *

algorithm = b'\x00'
oob_public_key = b'\x00' # No oob public key
authentication_method = b'\x02' # Output oob is used
authentication_action = b'\x04' # Display string

NetworkKey = b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00'
KeyIndex = b'\x00\x00'
Flags = b'\x00'
IVIndex = b'\x11\x22\x33\x44'
UnicastAddress = b'\xaa\xbb'

# Create and configure logger
logger = logging.getLogger('provisioner')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def start_outputOOB_provisioning(conn):
    try:
        # TODO 1. Receive Beacon
        beacon_message = #TODO
        logger.info(f'Received Beacon Message: {beacon_message.hex()}')


        # TODO 2. Send link open message
        link_open_message = #TODO
        conn.send(link_open_message)
        logger.info(f'Send Link Open Message: {link_open_message.hex()}')

        # TODO 3. Receive Link Ack Message
        link_ack_message = #TODO

        # TODO 4. Provisioning starts
        # Implement the provisioning process here

        # TODO 5. Link close
        link_close_message = #TODO
        conn.send(link_close_message)

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

def start_server(host='127.0.0.1', port=65432):
    server = listen(port, bindaddr=host)
    logger.info(f'Server listening on {host}:{port}')

    connection = server.wait_for_connection()
    logger.info(f'Connected by {connection.rhost}:{connection.rport}')

    start_outputOOB_provisioning(connection)

if __name__ == "__main__":
    start_server()
