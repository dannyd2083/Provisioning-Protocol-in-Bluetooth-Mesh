#!/usr/bin/env python3
import logging
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from toolbox import *

DeviceUUID = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
OOBInfo = b'\x04\x00' # Type of Number
URIdata = b'This is URI data'

# Provisioning Capabilities
number_of_elements = b'\x01'
algorithms = b'\x00\x00'
public_key_type = b'\x00'
static_oob_type = b'\x00'
output_oob_size = b'\x08' # Output OOB is available (8 bytes long)
output_oob_action = b'\x00\x10' # Show a string
input_oob_size = b'\x00'
input_oob_action = b'\x00\x00'

# Create and configure logger
logger = logging.getLogger('device')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def start_outputOOB_provisioning(host, port):
    conn = remote(host, port)
    logger.info(f'Connected to server at {host}:{port}')

    try:
        #TODO 1. Send Beacon
        beacon = #TODO
        conn.send(beacon)
        logger.info(f'Sent Beacon: {beacon.hex()}')

        #TODO 2. Receive Link Open Message
        link_open_message = #TODO
        logger.info(f'Received Link Open Message: {link_open_message.hex()}')

        #TODO 3. Send Link Ack Message
        link_ack_message = #TODO
        conn.send(link_ack_message)

        #TODO 4. Provisioning starts
        # Implement the provisioning process here

        #TODO 5. Send Provisioning Complete
        complete_message = #TODO
        conn.send(complete_message)

        #TODO 6. Receive Link Close Message
        link_close_message = #TODO
        logger.info(f'Received Link Close Message: {link_close_message.hex()}')

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

if __name__ == "__main__":
    start_outputOOB_provisioning('127.0.0.1', 65433)
