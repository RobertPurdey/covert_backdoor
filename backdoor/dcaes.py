import os
import random
import struct
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
import hashlib
from Crypto import Random

CHUNKSIZE = 64 * 1024
FILENAME_BUFLEN = 64
FILESIZE_BUFLEN = struct.calcsize('Q')
IV_LEN = 16
BLOCK_SIZE = 16


pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Encryption tool used to encrypt and decrypt strings and files.
    """
    def __init__(self, key):
        self.key = hashlib.md5(key.encode('utf8')).hexdigest()

    def encrypt_string(self, raw):
        """
        Encrypts a string using the key. Encrypts the string in one call and returns the encrypted string, base-64
        encoded.
        :param raw: The string to be encrypted
        :return: Base-64 encoded, AES-encrypted string
        """
        # strings to be encrypted must have a length of a multiple of 16
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt_string(self, enc):
        """
        Decrypts a string using the key.
        :param enc: The encrypted string to be decrypted
        :return: Decoded, decrypted string
        """
        if len(enc) <= 16:
            return ''
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

    def encrypt_file(self, infile_name):
        """
        Encrypts a file using key. Uses AES from PyCrypto to encrypt a file in 16-byte chunks.
        The file name will also be encrypted into the return string, along with the un-encrypted size of the file.
        :param key: The key used to ecrypt the file.
        :param infile_name: The name/location of the file to encrypt
        :return: str - A string representing the encrypted file, along with its size and name
        """
        # sha hash the key
        key = hashlib.sha256(self.key).digest()
        # set a random initialization vector
        iv = ''.join(chr(random.randint(0, 0xFF)) for _ in range(IV_LEN))
        enc = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(infile_name)

        enc_string = (struct.pack('<Q', filesize))
        enc_string += iv
        enc_string += (enc.encrypt(struct.pack(str(FILENAME_BUFLEN) + 's', os.path.basename(infile_name))))

        with open(infile_name, 'rb') as infile:
            while True:
                chunk = infile.read(CHUNKSIZE)
                if len(chunk) == 0:
                    break
                # Pad the last chunk with spaces if it's not 16 bytes long
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                enc_string += (enc.encrypt(chunk))

        return enc_string

    def decrypt_file(self, infile_name):
        """
        Decrypts a file, writing the decrypted result to a separate file.
        :param infile_name: The name/location of the file to decrypt
        :return: True if the file was decrypted successfully. False otherwise.
        """
        key = hashlib.sha256(self.key).digest()

        try:
            with open(infile_name, 'rb') as infile:
                filesize = struct.unpack('<Q', str(infile.read(FILESIZE_BUFLEN)))[0]
                iv = infile.read(IV_LEN)
                dec = AES.new(key, AES.MODE_CBC, iv)
                filename = dec.decrypt(struct.unpack(str(FILENAME_BUFLEN) + 's', str(infile.read(FILENAME_BUFLEN)))[0])
                filename = filename.rstrip('\x00')

                try:
                    with open(filename, 'wb') as outfile:
                        while True:
                            chunk = infile.read(CHUNKSIZE)
                            if len(chunk) == 0 or len(chunk) != CHUNKSIZE:
                                break
                            outfile.write(dec.decrypt(chunk))

                        outfile.truncate(filesize)
                except IOError as e:
                    print("IOError!: " + str(e))
                    return False
        except IOError as e:
            print("IOError!: " + str(e))
            return False

        return True

