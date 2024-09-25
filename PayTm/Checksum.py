# pip install pycryptodome
import base64
import string
import random
import hashlib
from Crypto.Cipher import AES

IV = "@@@@&&&&####$$$$"
BLOCK_SIZE = 16

def generate_checksum(param_dict, MK, salt=None):
    params_string = __get_param_string__(param_dict)
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (params_string, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()

    hash_string += salt

    return __encode__(hash_string, IV, MK)

def generate_refund_checksum(param_dict, MK, salt=None):
    # Ensure no invalid characters in values
    if any("|" in value for value in param_dict.values()):
        raise ValueError("Invalid character '|' in parameter values.")
        
    params_string = __get_param_string__(param_dict)
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (params_string, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()

    hash_string += salt

    return __encode__(hash_string, IV, MK)

def generate_checksum_by_str(param_str, MK, salt=None):
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (param_str, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()

    hash_string += salt

    return __encode__(hash_string, IV, MK)

def verify_checksum(param_dict, MK, checksum):
    if 'CHECKSUMHASH' in param_dict:
        param_dict.pop('CHECKSUMHASH')
        
    paytm_hash = __decode__(checksum, IV, MK)
    salt = paytm_hash[-4:]
    calculated_checksum = generate_checksum(param_dict, MK, salt=salt)
    
    return calculated_checksum == checksum

def verify_checksum_by_str(param_str, MK, checksum):
    paytm_hash = __decode__(checksum, IV, MK)
    salt = paytm_hash[-4:]
    calculated_checksum = generate_checksum_by_str(param_str, MK, salt=salt)
    
    return calculated_checksum == checksum

def __id_generator__(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))

def __get_param_string__(params):
    params_string = []
    for key in sorted(params.keys()):
        if "REFUND" in params[key] or "|" in params[key]:
            raise ValueError("Invalid character '|' or 'REFUND' in parameter values.")
        value = params[key]
        params_string.append('' if value == 'null' else str(value))
    return '|'.join(params_string)

def __pad__(s):
    padding_needed = BLOCK_SIZE - len(s) % BLOCK_SIZE
    return s + (chr(padding_needed) * padding_needed)

def __unpad__(s):
    if s:
        padding_char = s[-1]
        return s[:-ord(padding_char)]
    return s

def __encode__(to_encode, iv, key):
    to_encode = __pad__(to_encode)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    encrypted = cipher.encrypt(to_encode.encode('utf-8'))
    return base64.b64encode(encrypted).decode("UTF-8")

def __decode__(to_decode, iv, key):
    decoded = base64.b64decode(to_decode)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    decrypted = cipher.decrypt(decoded).decode()
    return __unpad__(decrypted)

if __name__ == "__main__":
    params = {
        "MID": "mid",
        "ORDER_ID": "order_id",
        "CUST_ID": "cust_id",
        "TXN_AMOUNT": "1",
        "CHANNEL_ID": "WEB",
        "INDUSTRY_TYPE_ID": "Retail",
        "WEBSITE": "xxxxxxxxxxx"
    }

    # Example for testing
    checksum = "CD5ndX8VVjlzjWbbYoAtKQIlvtXPypQYOg0Fi2AUYKXZA5XSHiRF0FDj7vQu66S8MHx9NaDZ/uYm3WBOWHf+sDQAmTyxqUipA7i1nILlxrk="
    mk = "xxxxxxxxxxxxxxxx"
    
    print(verify_checksum(params, mk, checksum))
    print(generate_checksum(params, mk))
