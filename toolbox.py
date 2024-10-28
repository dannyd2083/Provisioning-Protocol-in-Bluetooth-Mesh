from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from cryptography.hazmat.primitives.asymmetric import ec
import random, string

BEACON_TYPE = b'\x00'
# Link Management Opcodes
LINK_OPEN_OPCODE = b'\x03'  # 0x00 (6 bits) || 11 (binary) = 0x03
LINK_ACK_OPCODE = b'\x07'  # 0x01 (6 bits) || 11 (binary) = 0x07
LINK_CLOSE_OPCODE = b'\x0B'  # 0x02 (6 bits) || 11 (binary) = 0x0B

# Provisioning PDUs Opcodes
PROVISIONING_INVITE_OPCODE = b'\x00'  # 0x00 padded to 8 bits
PROVISIONING_CAPABILITIES_OPCODE = b'\x01'  # 0x01 padded to 8 bits
PROVISIONING_START_OPCODE = b'\x02'  # 0x02 padded to 8 bits
PROVISIONING_PUBLIC_KEY_OPCODE = b'\x03'  # 0x03 padded to 8 bits
PROVISIONING_INPUT_COMPLETE_OPCODE = b'\x04'  # 0x04 padded to 8 bits
PROVISIONING_CONFIRMATION_OPCODE = b'\x05'  # 0x05 padded to 8 bits
PROVISIONING_RANDOM_OPCODE = b'\x06'  # 0x06 padded to 8 bits
PROVISIONING_DATA_OPCODE = b'\x07'  # 0x07 padded to 8 bits
PROVISIONING_COMPLETE_OPCODE = b'\x08'  # 0x08 padded to 8 bits
PROVISIONING_FAILED_OPCODE = b'\x09'  # 0x09 padded to 8 bits

attention_duration = b'\x00'

def generate_random_string(n):
    """
    Generate a random string of length n.

    Args:
    - n (int): The length of the random string.

    Returns:
    - str: The generated random string.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def generate_key_pair():
    """
    Generate a new public-private key pair using the FIPS P-256 algorithm.

    Returns:
    - private_key: The generated private key.
    - public_key_x: The X component of the public key.
    - public_key_y: The Y component of the public key.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    public_key_x = public_numbers.x.to_bytes(32, 'big')
    public_key_y = public_numbers.y.to_bytes(32, 'big')
    return private_key, public_key_x, public_key_y

def derive_dhkey(private_key, public_key_x, public_key_y):
    """
    Derive the DHKey using the private key and the peer's public key components.

    Args:
    - private_key: The private key.
    - public_key_x: The X component of the peer's public key.
    - public_key_y: The Y component of the peer's public key.

    Returns:
    - bytes: The derived DHKey.
    """
    peer_public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(public_key_x, 'big'),
        int.from_bytes(public_key_y, 'big'),
        ec.SECP256R1()
    )
    peer_public_key = peer_public_numbers.public_key()
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def s1(M):
    """
    M is a non-zero length octet array or ASCII encoded string
    """
    #TODO: Implement this function
    return b'\x00'

def k1(N, SALT, P):
    """
    Derive a key using the k1 function.

    Args:
    - N: The input value.
    - SALT: The salt value.
    - P: The input value.

    Returns:
    - bytes: The derived key.
    """
    # TODO: Implement this function
    return b'\x00'
