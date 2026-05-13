"""
SM4 Implementation - GB/T 32907-2016 Compliant
Primary implementation using gmssl library
"""

try:
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
    HAS_GMSSL = True
except ImportError:
    HAS_GMSSL = False
    CryptSM4 = None
    SM4_ENCRYPT = 1
    SM4_DECRYPT = 0

import os


def generate_random_key():
    """Generate random 128-bit SM4 key"""
    return os.urandom(16)


def generate_random_iv():
    """Generate random 128-bit IV"""
    return os.urandom(16)


def bytes_to_hex(data):
    """Convert bytes to hex string"""
    return data.hex()


def hex_to_bytes(hex_str):
    """Convert hex string to bytes"""
    hex_str = hex_str.replace(' ', '').replace('-', '')
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string must have even length")
    return bytes.fromhex(hex_str)


def bytes_to_base64(data):
    """Convert bytes to Base64 string"""
    import base64
    return base64.b64encode(data).decode('ascii')


def base64_to_bytes(base64_str):
    """Convert Base64 string to bytes"""
    import base64
    return base64.b64decode(base64_str)


def validate_key(key_str, key_type='hex'):
    """Validate and convert key input"""
    if key_type == 'hex':
        key_bytes = hex_to_bytes(key_str)
    elif key_type == 'base64':
        key_bytes = base64_to_bytes(key_str)
    elif key_type == 'bytes':
        key_bytes = key_str
    else:
        raise ValueError("Invalid key type")

    if len(key_bytes) != 16:
        raise ValueError(f"Key must be 128 bits (16 bytes), got {len(key_bytes)} bytes")

    return key_bytes


def validate_iv(iv_str, iv_type='hex'):
    """Validate and convert IV input"""
    if iv_str is None:
        return None

    if iv_type == 'hex':
        iv_bytes = hex_to_bytes(iv_str)
    elif iv_type == 'base64':
        iv_bytes = base64_to_bytes(iv_str)
    elif iv_type == 'bytes':
        iv_bytes = iv_str
    else:
        raise ValueError("Invalid IV type")

    if len(iv_bytes) != 16:
        raise ValueError(f"IV must be 128 bits (16 bytes), got {len(iv_bytes)} bytes")

    return iv_bytes


def pkcs7_padding(data):
    """Add PKCS7 padding"""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len]) * padding_len


def pkcs7_unpadding(data):
    """Remove PKCS7 padding"""
    if not data:
        return data
    padding_len = data[-1]
    if 1 <= padding_len <= 16 and padding_len <= len(data):
        return data[:-padding_len]
    return data


def zero_padding(data):
    """Add zero padding"""
    padding_len = 16 - (len(data) % 16)
    if padding_len == 16:
        return data
    return data + bytes(padding_len)


def zero_unpadding(data):
    """Remove zero padding"""
    if not data:
        return data
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    return data[:i+1] if i >= 0 else data


def sm4_encrypt(key, plaintext, mode='ECB', iv=None, padding=True, padding_mode='PKCS7'):
    """Encrypt using SM4"""
    if not HAS_GMSSL:
        raise RuntimeError("gmssl library required. Install: pip install gmssl")

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    cipher = CryptSM4()
    cipher.set_key(key, SM4_ENCRYPT)

    if mode.upper() == 'ECB':
        if padding:
            if padding_mode == 'PKCS7':
                plaintext = pkcs7_padding(plaintext)
            elif padding_mode == 'ZeroPadding':
                plaintext = zero_padding(plaintext)

        return cipher.crypt_ecb(plaintext)

    elif mode.upper() == 'CBC':
        if iv is None:
            iv = generate_random_iv()

        if padding:
            if padding_mode == 'PKCS7':
                plaintext = pkcs7_padding(plaintext)
            elif padding_mode == 'ZeroPadding':
                plaintext = zero_padding(plaintext)

        return cipher.crypt_cbc(iv, plaintext)

    elif mode.upper() in ['CFB', 'OFB']:
        if iv is None:
            iv = generate_random_iv()

        data = bytearray(plaintext)
        result = bytearray()
        iv_temp = bytearray(iv)
        cipher_temp = CryptSM4()
        cipher_temp.set_key(key, SM4_ENCRYPT)

        block_size = 16

        for i in range(0, len(data), block_size):
            keystream = cipher_temp.crypt_ecb(bytes(iv_temp))

            block = data[i:i+block_size]
            for j in range(len(block)):
                result.append(block[j] ^ keystream[j])

            if mode.upper() == 'CFB':
                iv_temp = bytearray(result[-16:]) if len(result) >= 16 else bytearray(result) + bytearray(iv_temp[len(result):])
            else:
                iv_temp = bytearray(keystream)

        return bytes(result)

    else:
        raise ValueError(f"Unsupported mode: {mode}")


def sm4_decrypt(key, ciphertext, mode='ECB', iv=None, padding=True, padding_mode='PKCS7'):
    """Decrypt using SM4"""
    if not HAS_GMSSL:
        raise RuntimeError("gmssl library required. Install: pip install gmssl")

    decipher = CryptSM4()
    decipher.set_key(key, SM4_DECRYPT)

    if mode.upper() == 'ECB':
        plaintext = decipher.crypt_ecb(ciphertext)

        if padding:
            if padding_mode == 'PKCS7':
                plaintext = pkcs7_unpadding(plaintext)
            elif padding_mode == 'ZeroPadding':
                plaintext = zero_unpadding(plaintext)

        return plaintext

    elif mode.upper() == 'CBC':
        if iv is None:
            raise ValueError("CBC mode requires IV")

        plaintext = decipher.crypt_cbc(iv, ciphertext)

        if padding:
            if padding_mode == 'PKCS7':
                plaintext = pkcs7_unpadding(plaintext)
            elif padding_mode == 'ZeroPadding':
                plaintext = zero_unpadding(plaintext)

        return plaintext

    elif mode.upper() in ['CFB', 'OFB']:
        if iv is None:
            iv = generate_random_iv()

        data = bytearray(ciphertext)
        result = bytearray()
        iv_temp = bytearray(iv)
        cipher_temp = CryptSM4()
        cipher_temp.set_key(key, SM4_ENCRYPT)

        block_size = 16

        for i in range(0, len(data), block_size):
            keystream = cipher_temp.crypt_ecb(bytes(iv_temp))

            block = data[i:i+block_size]
            for j in range(len(block)):
                result.append(block[j] ^ keystream[j])

            if mode.upper() == 'CFB':
                iv_temp = bytearray(data[i:i+block_size])
            else:
                iv_temp = bytearray(keystream)

        return bytes(result)

    else:
        raise ValueError(f"Unsupported mode: {mode}")


def sm4_encrypt_file(key, input_file, output_file, mode='ECB', iv=None, padding=True, padding_mode='PKCS7'):
    """Encrypt file with SM4"""
    with open(input_file, 'rb') as fin:
        plaintext = fin.read()

    ciphertext = sm4_encrypt(key, plaintext, mode, iv, padding, padding_mode)

    with open(output_file, 'wb') as fout:
        if mode.upper() == 'CBC' and iv is not None:
            fout.write(iv)
        fout.write(ciphertext)


def sm4_decrypt_file(key, input_file, output_file, mode='ECB', iv=None, padding=True, padding_mode='PKCS7'):
    """Decrypt file with SM4"""
    with open(input_file, 'rb') as fin:
        if mode.upper() in ['CBC', 'CFB', 'OFB']:
            stored_iv = fin.read(16)
            if iv is None:
                iv = stored_iv
        ciphertext = fin.read()

    plaintext = sm4_decrypt(key, ciphertext, mode, iv, padding, padding_mode)

    with open(output_file, 'wb') as fout:
        fout.write(plaintext)


if __name__ == '__main__':
    print("SM4 Encryption Tool - GB/T 32907-2016")
    print("=" * 60)

    if not HAS_GMSSL:
        print("ERROR: gmssl library not found")
        print("Please install: pip install gmssl")
        exit(1)

    print("Testing SM4 encryption...")

    key = generate_random_key()
    iv = generate_random_iv()
    plaintext = b"Hello, SM4! This is a test message."

    print(f"Key: {bytes_to_hex(key)}")
    print(f"IV:  {bytes_to_hex(iv)}")
    print(f"Plaintext: {plaintext}")

    print("\nECB Mode:")
    ct_ecb = sm4_encrypt(key, plaintext, 'ECB')
    print(f"Ciphertext: {bytes_to_hex(ct_ecb)}")
    pt_ecb = sm4_decrypt(key, ct_ecb, 'ECB')
    print(f"Decrypted: {pt_ecb}")
    print(f"Match: {pt_ecb == plaintext}")

    print("\nCBC Mode:")
    ct_cbc = sm4_encrypt(key, plaintext, 'CBC', iv)
    print(f"Ciphertext: {bytes_to_hex(ct_cbc)}")
    pt_cbc = sm4_decrypt(key, ct_cbc, 'CBC', iv)
    print(f"Decrypted: {pt_cbc}")
    print(f"Match: {pt_cbc == plaintext}")

    print("\n" + "=" * 60)
    print("All tests passed!" if pt_ecb == plaintext and pt_cbc == plaintext else "Some tests failed!")
