"""
SM4 Block Cipher Modes Implementation
Supports ECB, CBC, CFB, OFB modes
"""

import os
from sm4_core import SM4


class SM4ECB:
    """Electronic Codebook (ECB) mode"""

    @staticmethod
    def encrypt(key, plaintext, padding=True):
        """Encrypt plaintext"""
        cipher = SM4(key)
        data = bytearray(plaintext)

        if padding:
            padding_len = 16 - (len(data) % 16)
            data.extend([padding_len] * padding_len)
        elif len(data) % 16 != 0:
            raise ValueError("Data must be multiple of 16 bytes without padding")

        ciphertext = bytearray()
        for i in range(0, len(data), 16):
            ciphertext.extend(cipher.encrypt_block(bytes(data[i:i+16])))

        return bytes(ciphertext)

    @staticmethod
    def decrypt(key, ciphertext, padding=True):
        """Decrypt ciphertext"""
        cipher = SM4(key)
        data = bytearray(ciphertext)

        if len(data) % 16 != 0:
            raise ValueError("Ciphertext must be multiple of 16 bytes")

        plaintext = bytearray()
        for i in range(0, len(data), 16):
            plaintext.extend(cipher.decrypt_block(bytes(data[i:i+16])))

        if padding:
            padding_len = plaintext[-1]
            if 1 <= padding_len <= 16 and padding_len <= len(plaintext):
                plaintext = plaintext[:-padding_len]

        return bytes(plaintext)


class SM4CBC:
    """Cipher Block Chaining (CBC) mode"""

    @staticmethod
    def encrypt(key, plaintext, iv, padding=True):
        """Encrypt plaintext with IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes)")

        cipher = SM4(key)
        data = bytearray(plaintext)
        iv_temp = bytearray(iv)

        if padding:
            padding_len = 16 - (len(data) % 16)
            data.extend([padding_len] * padding_len)
        elif len(data) % 16 != 0:
            raise ValueError("Data must be multiple of 16 bytes without padding")

        ciphertext = bytearray()
        for i in range(0, len(data), 16):
            block = bytes([data[j] ^ iv_temp[j] for j in range(16)])
            encrypted = cipher.encrypt_block(block)
            ciphertext.extend(encrypted)
            iv_temp = bytearray(encrypted)

        return bytes(ciphertext)

    @staticmethod
    def decrypt(key, ciphertext, iv, padding=True):
        """Decrypt ciphertext with IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes)")

        cipher = SM4(key)
        data = bytearray(ciphertext)

        if len(data) % 16 != 0:
            raise ValueError("Ciphertext must be multiple of 16 bytes")

        plaintext = bytearray()
        iv_temp = bytearray(iv)

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            decrypted = cipher.decrypt_block(bytes(block))
            plain_block = bytes([decrypted[j] ^ iv_temp[j] for j in range(16)])
            plaintext.extend(plain_block)
            iv_temp = block

        if padding:
            padding_len = plaintext[-1]
            if 1 <= padding_len <= 16 and padding_len <= len(plaintext):
                plaintext = plaintext[:-padding_len]

        return bytes(plaintext)


class SM4CFB:
    """Cipher Feedback (CFB) mode - 128-bit feedback"""

    @staticmethod
    def encrypt(key, plaintext, iv):
        """Encrypt plaintext with IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes)")

        cipher = SM4(key)
        data = bytearray(plaintext)
        iv_temp = bytearray(iv)

        ciphertext = bytearray()
        for i in range(0, len(data), 16):
            encrypted = cipher.encrypt_block(bytes(iv_temp))
            block_size = min(16, len(data) - i)
            for j in range(block_size):
                ciphertext.append(data[i + j] ^ encrypted[j])
                iv_temp[j] = ciphertext[i + j]
            if block_size < 16:
                iv_temp = bytearray(ciphertext[i:i+16])

        return bytes(ciphertext)

    @staticmethod
    def decrypt(key, ciphertext, iv):
        """Decrypt ciphertext with IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes)")

        cipher = SM4(key)
        data = bytearray(ciphertext)
        iv_temp = bytearray(iv)

        plaintext = bytearray()
        for i in range(0, len(data), 16):
            encrypted = cipher.encrypt_block(bytes(iv_temp))
            block_size = min(16, len(data) - i)
            for j in range(block_size):
                plaintext.append(data[i + j] ^ encrypted[j])
                iv_temp[j] = data[i + j]
            if block_size < 16:
                iv_temp = bytearray(data[i:i+16])

        return bytes(plaintext)


class SM4OFB:
    """Output Feedback (OFB) mode - 128-bit feedback"""

    @staticmethod
    def encrypt(key, plaintext, iv):
        """Encrypt plaintext with IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes)")

        cipher = SM4(key)
        data = bytearray(plaintext)
        iv_temp = bytearray(iv)

        ciphertext = bytearray()
        for i in range(0, len(data), 16):
            encrypted = cipher.encrypt_block(bytes(iv_temp))
            block_size = min(16, len(data) - i)
            for j in range(block_size):
                ciphertext.append(data[i + j] ^ encrypted[j])
                iv_temp[j] = encrypted[j]
            if block_size < 16:
                iv_temp = bytearray(ciphertext[i:i+16])

        return bytes(ciphertext)

    @staticmethod
    def decrypt(key, ciphertext, iv):
        """Decrypt ciphertext with IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 128 bits (16 bytes)")

        cipher = SM4(key)
        data = bytearray(ciphertext)
        iv_temp = bytearray(iv)

        plaintext = bytearray()
        for i in range(0, len(data), 16):
            encrypted = cipher.encrypt_block(bytes(iv_temp))
            block_size = min(16, len(data) - i)
            for j in range(block_size):
                plaintext.append(data[i + j] ^ encrypted[j])
                iv_temp[j] = encrypted[j]
            if block_size < 16:
                iv_temp = bytearray(plaintext[i:i+16])

        return bytes(plaintext)


def sm4_encrypt(key, plaintext, mode='ECB', iv=None, padding=True):
    """Encrypt using SM4 with specified mode"""
    mode = mode.upper()
    if mode == 'ECB':
        return SM4ECB.encrypt(key, plaintext, padding)
    elif mode == 'CBC':
        return SM4CBC.encrypt(key, plaintext, iv, padding)
    elif mode == 'CFB':
        return SM4CFB.encrypt(key, plaintext, iv)
    elif mode == 'OFB':
        return SM4OFB.encrypt(key, plaintext, iv)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def sm4_decrypt(key, ciphertext, mode='ECB', iv=None, padding=True):
    """Decrypt using SM4 with specified mode"""
    mode = mode.upper()
    if mode == 'ECB':
        return SM4ECB.decrypt(key, ciphertext, padding)
    elif mode == 'CBC':
        return SM4CBC.decrypt(key, ciphertext, iv, padding)
    elif mode == 'CFB':
        return SM4CFB.decrypt(key, ciphertext, iv)
    elif mode == 'OFB':
        return SM4OFB.decrypt(key, ciphertext, iv)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def sm4_encrypt_file(key, input_file, output_file, mode='ECB', iv=None, padding=True, chunk_size=1024*1024):
    """Encrypt file with SM4"""
    mode = mode.upper()

    with open(input_file, 'rb') as fin:
        plaintext = fin.read()

    ciphertext = sm4_encrypt(key, plaintext, mode, iv, padding)

    with open(output_file, 'wb') as fout:
        if mode != 'ECB' and iv is not None:
            fout.write(iv)
        fout.write(ciphertext)


def sm4_decrypt_file(key, input_file, output_file, mode='ECB', iv=None, padding=True, chunk_size=1024*1024):
    """Decrypt file with SM4"""
    mode = mode.upper()

    with open(input_file, 'rb') as fin:
        if mode != 'ECB' and iv is not None:
            stored_iv = fin.read(16)
            if iv is None:
                iv = stored_iv
        ciphertext = fin.read()

    plaintext = sm4_decrypt(key, ciphertext, mode, iv, padding)

    with open(output_file, 'wb') as fout:
        fout.write(plaintext)
