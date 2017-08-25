import sys
import socket
from CryptoMethods import *
import json
import os, sys
import binascii
from datetime import datetime

def packageSessionKey(sender, recipient, sessionKey):
    rsa = KeyExchangeProtocol()

    keyData = {}
    keyData['sender'] = sender
    keyData['sessionKey'] = sessionKey.encode('base64')
    keyDataString = json.dumps(keyData)

    bobPublicKey = open("public/" + recipient + "_public.der").read()
    encryptedKeyData = rsa.encrypt(keyDataString, bobPublicKey)

    msgWithMetadata = {}
    msgWithMetadata['B'] = recipient
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    msgWithMetadata['tA'] = datetime.now().strftime(fmt)
    msgWithMetadata['keyData'] = encryptedKeyData.encode('base64')
    msg = json.dumps(msgWithMetadata)

    alicePrivateKey = open(sender + "/" + sender + "_private.der").read()
    signature = rsa.sign(msg, alicePrivateKey)

    signedMsg = {}
    signedMsg['msg'] = msg
    signedMsg['signature'] = signature.encode('base64')
    signedMsgString = json.dumps(signedMsg)

    return signedMsgString

def packageMessage(mode, msg, sessionKey):
    if (mode == '-n'):
        return msg
    elif (mode == '-e'):
        aes = AES256(sessionKey)
        return aes.encrypt(msg)
    elif (mode == '-m'):
        mac = HMAC_SHA512(sessionKey)
        return mac.appendMAC(msg)
    elif (mode == '-em'):
        aes = AES256(sessionKey)
        encryptedMsg = aes.encrypt(msg)
        mac = HMAC_SHA512(sessionKey)
        return mac.appendMAC(encryptedMsg)


if __name__ == "__main__":
    mode = sys.argv[1]
    address = sys.argv[2]
    port = int(sys.argv[3])

    mallorySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mallorySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mallorySocket.connect((address, port))

    sessionKey = os.urandom(32)
    sessionKeyMsg = packageSessionKey('Alice','Bob', sessionKey)
    mallorySocket.send(sessionKeyMsg)

    try:
        seqNumber = 1
        while True:
            if (seqNumber == sys.maxint):
                print("Sequence number will wrap around. Terminating session.")
                mallorySocket.close()
                break
            msg = raw_input("Enter msg:\n")
            labeledMsg = {}
            labeledMsg['msg'] = msg
            labeledMsg['seqNumber'] = seqNumber
            packagedMsg = packageMessage(mode, json.dumps(labeledMsg), sessionKey)
            mallorySocket.send(packagedMsg)
            seqNumber += 1
    except socket.error as e:
        print("Connection terminated by client.")