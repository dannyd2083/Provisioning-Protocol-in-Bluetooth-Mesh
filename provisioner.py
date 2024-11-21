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

def process_auth_value(input_string):
    # Convert the string to proper 128-bit auth value
    auth_bytes = input_string.encode('ascii')
    logger.info(f'auth_bytes before shift: {auth_bytes.hex()}')
    auth_value = auth_bytes.ljust(16, b'\x00')
    logger.info(f'auth_value: {auth_value.hex()}')
    return auth_value


def calculate_confirmation(confirmation_inputs, auth_value, priv_key, dev_pub_x, dev_pub_y,random_value=None):
    """Calculate the confirmation value according to spec."""
    # Generate DHKey
    dhkey = derive_dhkey(priv_key, dev_pub_x, dev_pub_y)
    logger.info(f"dhkey :{dhkey.hex()}")

    # Calculate confirmation salt = s1(ConfirmationInputs)
    confirmation_salt = s1(confirmation_inputs)
    logger.info(f"confirmation_salt :{confirmation_salt.hex()}")

    # Calculate confirmation key = k1(ECDHSecret, ConfirmationSalt, "prck")
    confirmation_key = k1(dhkey, confirmation_salt, b'prck')
    logger.info(f"confirmation_key :{confirmation_key.hex()}")

    # Generate random value for the exchange
    if random_value is None:
        # Generate random value for the exchange
        random_value = get_random_bytes(16)
        logger.info(f"Generated new random_value: {random_value.hex()}")
    else:
        logger.info(f"Using provided random_value: {random_value.hex()}")

    # Calculate confirmation using AES-CMAC
    cmac = CMAC.new(confirmation_key, ciphermod=AES)
    cmac.update(random_value + auth_value)
    confirmation = cmac.digest()

    return confirmation, random_value

def start_outputOOB_provisioning(conn):
    try:
        # TODO 1. Receive Beacon
        beacon_message = conn.recv()
        device_uuid =  beacon_message[1:17]
        oob_info = beacon_message[17:19]
        logger.info(f'Received Beacon Message: {beacon_message.hex()}')

        # TODO 2. Send link open message

        link_open_message = LINK_OPEN_OPCODE + device_uuid
        conn.send(link_open_message)
        logger.info(f'Send Link Open Message: {link_open_message.hex()}')

        # TODO 3. Receive Link Ack Message
        link_ack_message = conn.recv()
        logger.info(f'Received Link Ack Message: {link_ack_message.hex()}')
        if link_ack_message[0:1] == LINK_ACK_OPCODE:
            # TODO 4. Provisioning starts
            # Implement the provisioning process here

            # 4.1 Send Provisioning Invite
            invite = PROVISIONING_INVITE_OPCODE + attention_duration
            conn.send(invite)
            logger.info(f'Sent Provisioning Invite: {invite.hex()}')

            # 4.2 Receive Capabilities
            capabilities = conn.recv()
            logger.info(f'Received Capabilities: {capabilities.hex()}')
            if capabilities[0:1] == PROVISIONING_CAPABILITIES_OPCODE:

                # 4.3 Send Provisioning Start
                output_oob_size = b'\x08'
                start_pdu = (PROVISIONING_START_OPCODE +
                             algorithm +
                             oob_public_key +
                             authentication_method +
                             authentication_action +
                             output_oob_size
                             )
                conn.send(start_pdu)
                logger.info(f'Sent Provisioning Start: {start_pdu.hex()}')

                # 4.4 Generate and exchange keys
                private_key, public_key_x, public_key_y = generate_key_pair()

                # Receive device's public key
                device_public_key = conn.recv()
                if device_public_key[0:1] == PROVISIONING_PUBLIC_KEY_OPCODE:
                    device_public_key_x = device_public_key[1:33]
                    device_public_key_y = device_public_key[33:]

                    logger.info(f'Received Device Public Key: {device_public_key.hex()}')

                    # Send provisioner's public key
                    public_key = PROVISIONING_PUBLIC_KEY_OPCODE + public_key_x + public_key_y
                    conn.send(public_key)
                    logger.info(f'Sent Public Key: {public_key.hex()}')

                    # Wait for user to input the string shown by device
                    auth_string = input("Enter the string displayed on device: ")
                    auth_value = process_auth_value(auth_string)
                    logger.info(f'Processed auth value from input: {auth_value.hex()}')
                    # Construct confirmation inputs
                    confirmation_inputs = (
                            invite[1:] +
                            capabilities[1:] +
                            start_pdu[1:] +
                            public_key[1:] +
                            device_public_key[1:]
                    )

                    logger.info(f'Build confirmation_inputs: {confirmation_inputs.hex()}')

                    confirmation, random_value = calculate_confirmation(
                        confirmation_inputs,
                        auth_value,
                        private_key,
                        device_public_key_x,
                        device_public_key_y
                    )
                    conf_message = PROVISIONING_CONFIRMATION_OPCODE + confirmation
                    conn.send(conf_message)
                    logger.info(f'Sent Confirmation: {conf_message.hex()}')

                    # Receive device confirmation
                    device_confirmation = conn.recv()
                    logger.info(f'Received Device Confirmation: {device_confirmation.hex()}')

                    if device_confirmation[0:1] == PROVISIONING_CONFIRMATION_OPCODE:

                        # Receive device random
                        device_random = conn.recv()
                        logger.info(f'Received Device Random: {device_random.hex()}')
                        if device_random[0:1] == PROVISIONING_RANDOM_OPCODE:
                            device_random_value = device_random[1:]  # Remove opcode
                            # Send provisioner random
                            random_message = PROVISIONING_RANDOM_OPCODE + random_value
                            conn.send(random_message)
                            logger.info(f'Sent Random: {random_message.hex()}')

                            cal_confirmation, _ = calculate_confirmation(confirmation_inputs, auth_value, private_key,
                                                                     device_public_key_x, device_public_key_y,
                                                                     random_value=device_random_value)
                            logger.info(f'Calculate Confirmation: {cal_confirmation.hex()}')

                            if cal_confirmation != device_confirmation[1:]:
                                logger.error("Confirm values do not match. Pairing failed.")
                                # Send Pairing Failed packet (if desired)
                                conn.close()
                                return
                            # Encrypt and send provisioning data
                            dhkey = derive_dhkey(private_key,device_public_key_x,device_public_key_y)
                            # Calculate salts
                            confirmation_salt = s1(confirmation_inputs)
                            prov_salt = s1(confirmation_salt + random_value + device_random_value)
                            # Calculate session key using k1
                            session_key = k1(dhkey,prov_salt,b'prsk')
                            # Calculate nonce using k1, shall be the last 13 least sig octets
                            nonce =k1(dhkey,prov_salt,b'prsn')[:13]
                            # Prepare provisioning data
                            prov_data = NetworkKey + KeyIndex + Flags + IVIndex + UnicastAddress
                            # Create cipher
                            cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=8)
                            # Encrypt data
                            cipher.update(b'')
                            encrypted_data, mic = cipher.encrypt_and_digest(prov_data)
                            final_encrypted_data = encrypted_data + mic

                            prov_data_message = PROVISIONING_DATA_OPCODE + final_encrypted_data
                            conn.send(prov_data_message)
                            logger.info(f'Sent Encrypted Provisioning Data: {prov_data_message.hex()}')

                            # Receive provisioning complete
                            complete_message = conn.recv()
                            logger.info(f'Received Complete Message: {complete_message.hex()}')

                            # TODO 5. Link close
                            if complete_message[0:1] == PROVISIONING_COMPLETE_OPCODE:
                                # Send Link Close
                                link_close_message = LINK_CLOSE_OPCODE
                                conn.send(link_close_message)
                                logger.info(f'Sent Link Close Message: {link_close_message.hex()}')
                            else:
                                logger.error("Did not receive expected complete message")
                                conn.close()
                                return
                        else:
                            logger.error("Did not receive random value from device")
                            conn.close()
                            return
                    else:
                        logger.error("Did not receive device PROVISIONING_CONFIRMATION")
                        conn.close()
                        return
                else:
                    logger.error("Did not receive expected public key.")
                    conn.close()
                    return
            else:
                logger.error("Did not receive expected provisioning capabilities.")
                conn.close()
                return
        else:
            logger.error("Did not receive expected link ack message.")
            conn.close()
            return

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
