#!/usr/bin/env python3
import logging
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from toolbox import *
import select

# Create and configure logger
logger = logging.getLogger('attacker')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def fake_prov(s_prov, data):
    #TODO
    pass

def fake_dev(s_dev, s_prov, data):
    #TODO
    pass

def sniff():
    # Attacker acts as the middle man, she can sniff and modify all the data between the initiator and the responder
    # To emulate this, the attacker connects to the provisioner and the device to relay the data between them.
    prov_host = '127.0.0.1'
    prov_port = 65432
    prov_conn = remote(prov_host, prov_port)

    dev_host = '127.0.0.1'
    dev_port = 65433
    server = listen(dev_port, bindaddr=dev_host)
    dev_conn = server.wait_for_connection()

    sockets = [dev_conn, prov_conn]

    while True:
        readable, _, _ = select.select(sockets, [], [])
        for s in readable:
            if s == dev_conn:
                data = dev_conn.recv()
                fake_prov(prov_conn, data)
            elif s == prov_conn:
                data = prov_conn.recv()
                fake_dev(dev_conn, s, data)


if __name__ == "__main__":
    sniff()