from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
import json, hashlib, os

class KeyExchangeProtocol:

    def encrypt(self, sessionKeyInfo, publicKey):
        key = RSA.importKey(publicKey)
        cipher = PKCS1_OAEP.new(key)
        cipherText = cipher.encrypt(sessionKeyInfo)
        return cipherText

    def decrypt(self, cipherText, privateKey):
        key = RSA.importKey(privateKey)
        cipher = PKCS1_OAEP.new(key)
        sessionKeyInfo = cipher.decrypt(cipherText)
        return sessionKeyInfo

    def sign(self, msg, privateKey):
        key = RSA.importKey(privateKey)
        h = SHA512.new()
        h.update(msg)
        signer = PKCS1_PSS.new(key)
        signature = signer.sign(h)
        return signature

    def verify(self, msg, signature, publicKey):
        key = RSA.importKey(publicKey)
        h = SHA512.new()
        h.update(msg)
        verifier = PKCS1_PSS.new(key)
        return verifier.verify(h, signature)


class AES256:

    def __init__(self, key): 
        hash = hashlib.sha256()
        hash.update(key.encode('base64'))
        hash.update("Enc Alice to Bob")
        self.key = hash.digest()

    def encrypt(self, plaintext):
        plaintext = self.pad(plaintext)

        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        encryptedMsg = {}
        encryptedMsg['msg'] = cipher.encrypt(plaintext).encode('base64')
        encryptedMsg['iv'] = iv.encode('base64')
        encryptedMsgString = json.dumps(encryptedMsg)

        return encryptedMsgString

    def decrypt(self, msg):
        parsedMsg = json.loads(msg)
        ciphertext =  parsedMsg['msg'].decode('base64')
        iv = parsedMsg['iv'].decode('base64')
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = self.unpad(cipher.decrypt(ciphertext))
        parsedText = json.loads(plaintext)
        return plaintext

    # ACKNOWLEDGMENT: pad function by https://gist.github.com/swinton/8409454
    def pad(self, msg):
        return (msg + (AES.block_size - len(msg) % AES.block_size) * chr(AES.block_size - len(msg) % AES.block_size))

    # ACKNOWLEDGMENT: unpad function by https://gist.github.com/swinton/8409454
    def unpad(self, msg):
        return msg[:-ord(msg[len(msg)-1:])]


class HMAC_SHA512:

    def __init__(self, key):
        hash = hashlib.sha512()
        hash.update(key.encode('base64'))
        hash.update("MAC Alice to Bob")
        self.key = hash.digest()

    def appendMAC(self, msg):
        h = HMAC.new(self.key)
        h.update(msg)
        mac = h.hexdigest()
        macMsg = {}
        macMsg['msg'] = msg
        macMsg['mac'] = mac
        macMsgString = json.dumps(macMsg)
        return macMsgString

    def verifyMAC(self, msg):
        parsedMAC = json.loads(msg)
        h = HMAC.new(self.key)
        msgText =  parsedMAC['msg']
        mac = parsedMAC['mac']
        h.update(msgText)
        parsedMsg = json.loads(msgText)

        try:
            if (h.hexdigest() == mac):
                return msgText
            else:
                print parsedMsg['msg']
                raise ValueError
        except ValueError:
            print "\nMessage/key is corrupted."
