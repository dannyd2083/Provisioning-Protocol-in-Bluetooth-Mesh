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


def generate_auth_value(cap=8):
    # Generate random string
    auth_string = generate_random_string(cap)
    logger.info(f'Generated Output OOB string for display: {auth_string}')
    # Convert string to bytes and pad to 128 bits (16 bytes)
    auth_bytes = auth_string.encode('ascii')
    auth_value = auth_bytes.ljust(16, b'\x00')

    return auth_value, auth_string


def calculate_confirmation(confirmation_inputs, auth_value, priv_key,prov_pub_x, prov_pub_y,random_value=None):
    """Calculate the confirmation value according to spec."""
    # Generate DHKey
    dhkey = derive_dhkey(priv_key, prov_pub_x, prov_pub_y)
    logger.info(f"dhkey :{dhkey.hex()}")

    # Calculate confirmation salt = s1(ConfirmationInputs)
    confirmation_salt = s1(confirmation_inputs)
    logger.info(f"confirmation_salt :{confirmation_salt.hex()}")

    # Calculate confirmation key = k1(ECDHSecret, ConfirmationSalt, "prck")
    confirmation_key = k1(dhkey, confirmation_salt, b'prck')
    logger.info(f"confirmation_key :{confirmation_key.hex()}")

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

def start_outputOOB_provisioning(host, port):
    conn = remote(host, port)
    logger.info(f'Connected to server at {host}:{port}')

    try:
        #TODO 1. Send Beacon
        uri_hash = s1(URIdata)[:4]
        beacon = BEACON_TYPE + DeviceUUID + OOBInfo + uri_hash
        conn.send(beacon)
        logger.info(f'Sent Beacon: {beacon.hex()}')

        #TODO 2. Receive Link Open Message
        link_open_message = conn.recv()
        logger.info(f'Received Link Open Message: {link_open_message.hex()}')
        if link_open_message[0:1] == LINK_OPEN_OPCODE:
            #TODO 3. Send Link Ack Message
            link_ack_message = LINK_ACK_OPCODE
            conn.send(link_ack_message)

            #TODO 4. Provisioning starts
            # Implement the provisioning process here

            # 4.1 Receive Provisioning Invite
            stored_invite = conn.recv()
            logger.info(f'Received Provisioning Invite: {stored_invite.hex()}')
            if stored_invite[0:1] == PROVISIONING_INVITE_OPCODE:

                # 4.2 Receive Provisioning Invite
                capabilities = (PROVISIONING_CAPABILITIES_OPCODE +
                                number_of_elements +
                                algorithms +
                                public_key_type +
                                static_oob_type +
                                output_oob_size +
                                output_oob_action +
                                input_oob_size +
                                input_oob_action)
                conn.send(capabilities)
                logger.info(f'Sent Capabilities: {capabilities.hex()}')

                # 4.3 Receive Provisioning Start
                start_pdu = conn.recv()
                logger.info(f'Received Provisioning Start: {start_pdu.hex()}')
                if start_pdu[0:1] == PROVISIONING_START_OPCODE:

                    # 4.4 Generate and exchange keys
                    private_key, public_key_x, public_key_y = generate_key_pair()
                    public_key = PROVISIONING_PUBLIC_KEY_OPCODE + public_key_x + public_key_y
                    conn.send(public_key)
                    logger.info(f'Sent Public Key: {public_key.hex()}')

                    # Receive Provisioner's Public Key
                    provisioner_public_key = conn.recv()
                    if provisioner_public_key[0:1]== PROVISIONING_PUBLIC_KEY_OPCODE:
                        provisioner_public_key_x = provisioner_public_key[1:33]
                        provisioner_public_key_y = provisioner_public_key[33:]
                        logger.info(f'Received Provisioner Public Key: {provisioner_public_key.hex()}')

                        auth_value, display_string = generate_auth_value(8)
                        logger.info(f'Display this string to user: {display_string}')
                        logger.info("start the confirmation build")
                        # Construct confirmation inputs according to spec
                        confirmation_inputs = (
                                stored_invite[1:] +
                                capabilities[1:] +
                                start_pdu[1:] +
                                provisioner_public_key[1:] +
                                public_key[1:]
                        )

                        logger.info(f"confirmation input :{confirmation_inputs.hex()}")

                        logger.info(f'Wait user input and Provisioner Confirmation............')
                        prov_confirmation = conn.recv()
                        logger.info(f'Received Provisioner Confirmation: {prov_confirmation.hex()}')

                        if prov_confirmation[0:1] == PROVISIONING_CONFIRMATION_OPCODE:
                            confirmation, random_value = calculate_confirmation(
                                confirmation_inputs,
                                auth_value,
                                private_key,
                                provisioner_public_key_x,
                                provisioner_public_key_y
                            )

                            conf_message = PROVISIONING_CONFIRMATION_OPCODE + confirmation
                            conn.send(conf_message)
                            logger.info(f'Sent Confirmation: {conf_message.hex()}')

                            random_message = PROVISIONING_RANDOM_OPCODE + random_value
                            conn.send(random_message)
                            logger.info(f'Sent Random Value: {random_message.hex()}')

                            # Receive provisioner random
                            prov_random = conn.recv()
                            logger.info(f'Received Provisioner Random: {prov_random.hex()}')
                            if prov_random[0:1] == PROVISIONING_RANDOM_OPCODE:
                                prov_random_value = prov_random[1:]
                                cal_confirmation, _ = calculate_confirmation(confirmation_inputs, auth_value,
                                                                             private_key,
                                                                             provisioner_public_key_x,
                                                                             provisioner_public_key_y,
                                                                             random_value=prov_random_value)
                                logger.info(f'Calculate Confirmation: {cal_confirmation.hex()}')

                                if cal_confirmation != prov_confirmation[1:]:
                                    logger.error("Confirm values do not match. Pairing failed.")
                                    # Send Pairing Failed packet (if desired)
                                    conn.close()
                                    return

                                prov_data = conn.recv()
                                logger.info(f'Received Provisioning Data: {prov_data.hex()}')

                                if prov_data[0:1] == PROVISIONING_DATA_OPCODE:
                                    # Calculate salts and session keys
                                    confirmation_salt = s1(confirmation_inputs)
                                    prov_salt = s1(confirmation_salt + prov_random_value+ random_value)

                                    # Derive session key using k1
                                    dhkey = derive_dhkey(private_key, provisioner_public_key_x,
                                                         provisioner_public_key_y)
                                    session_key = k1(dhkey, prov_salt, b'prsk')

                                    # Get nonce (last 13 bytes of k1 result)
                                    nonce = k1(dhkey, prov_salt, b'prsn')[:13]
                                    # Extract encrypted data and MIC
                                    encrypted_data = prov_data[1:-8]  # Remove opcode and last 8 bytes (MIC)
                                    logger.info(f'Encrypted Provisioning Data: {encrypted_data.hex()}')
                                    mic = prov_data[-8:]  # Last 8 bytes are MIC

                                    # Create cipher for decryption
                                    cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=8)
                                    cipher.update(b'')

                                    try:
                                        # Decrypt and verify data
                                        decrypted_data = cipher.decrypt_and_verify(encrypted_data, mic)

                                        # Parse decrypted data
                                        network_key = decrypted_data[0:16]
                                        key_index = decrypted_data[16:18]
                                        flags = decrypted_data[18:19]
                                        iv_index = decrypted_data[19:23]
                                        unicast_address = decrypted_data[23:25]
                                        logger.info("Successfully decrypted provisioning data")
                                        logger.info(f"Network Key: {network_key.hex()}")
                                        logger.info(f"Key Index: {key_index.hex()}")
                                        logger.info(f"Flags: {flags.hex()}")
                                        logger.info(f"IV Index: {iv_index.hex()}")
                                        logger.info(f"Unicast Address: {unicast_address.hex()}")

                                        # TODO 5. Send Provisioning Complete
                                        # TODO
                                        # Send provisioning complete message
                                        complete_message = PROVISIONING_COMPLETE_OPCODE
                                        conn.send(complete_message)
                                        logger.info(f'Sent Complete Message: {complete_message.hex()}')

                                        # Wait for link close
                                        # TODO 6. Receive Link Close Message
                                        # TODO
                                        link_close = conn.recv()
                                        if link_close[0:1] == LINK_CLOSE_OPCODE:
                                            logger.info("Provisioning completed successfully")
                                            logger.info(f'Received Link Close Message: {link_close.hex()}')
                                        else:
                                            logger.error("Did not receive expected link close message")
                                    except ValueError as e:
                                        logger.error(f"Authentication failed: {e}")
                                        # Send provisioning failed message if needed
                                        conn.close()
                                        return
                            else:
                                logger.error("Did not receive random value from provisioner")
                                conn.close()
                                return
                        else:
                            logger.error("Did not receive provisioner PROVISIONING_CONFIRMATION")
                            conn.close()
                            return

                    else:
                        logger.error("Did not receive expected public key.")
                        conn.close()
                        return
                else:
                    logger.error("Did not receive expected provisioning start")
                    conn.close()
                    return
            else:
                logger.error("Did not receive expected provisioning invite")
                conn.close()
                return
        else:
            logger.error("Did not receive expected link open message.")
            conn.close()
            return

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

if __name__ == "__main__":
    start_outputOOB_provisioning('127.0.0.1', 65433)
