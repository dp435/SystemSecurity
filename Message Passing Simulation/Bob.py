import sys
import socket
from CryptoMethods import *
import json
from datetime import datetime


class KeyProcessingError(Exception):
    """Raised when session key deviates from expected behaviors."""
    pass


def processSessionKey(signedMsg, sender, recipient):
    try:
        parsedSignedMsg = json.loads(signedMsg)
        signature =  parsedSignedMsg['signature'].decode('base64')
        msg = parsedSignedMsg['msg']
        unpackedMsg = json.loads(msg)
        msgRecipient = unpackedMsg['B']
        tA = unpackedMsg['tA']
        cipherText = unpackedMsg['keyData'].decode('base64')

        rsa = KeyExchangeProtocol()
        bobPrivateKey = open(recipient + "/" + recipient +"_private.der").read()
        decryptedKeyData = rsa.decrypt(cipherText, bobPrivateKey)
        parsedKeyData = json.loads(decryptedKeyData)
        msgSender = parsedKeyData['sender']
        sessionKey = parsedKeyData['sessionKey'].decode('base64')

        alicePublicKey = open("public/" + sender +"_public.der").read()
        isVerified = rsa.verify(msg, signature, alicePublicKey)

        if (not(isVerified)):
            raise KeyProcessingError("Signature verification failed.")
        elif (recipient != msgRecipient):
            raise KeyProcessingError("Session key not intended for current user.")
        elif (sender != msgSender):
            raise KeyProcessingError("Session key did not originate from expected sender.")

        fmt = "%Y-%m-%d %H:%M:%S.%f"
        timeWhenGenerated = datetime.strptime(tA,fmt)
        currentTime = datetime.now()
        if ((currentTime - timeWhenGenerated).total_seconds() > 120):
            raise KeyProcessingError("Session key is not fresh.")

        return sessionKey

    except KeyProcessingError as e:
        print e
        raise KeyProcessingError(e)

    except Exception:
        print "Unexpected session key format: possible unauthorized modification."
        raise KeyProcessingError("Unexpected key format: possible unauthorized modification.")


def processMessage(mode, msg, sessionKey):
    if (mode == '-n'):
        return msg
    elif (mode == '-e'):
        aes = AES256(sessionKey)
        return aes.decrypt(msg)
    elif (mode == '-m'):
        mac = HMAC_SHA512(sessionKey)
        return mac.verifyMAC(msg)
    elif (mode == '-em'):
        mac = HMAC_SHA512(sessionKey)
        encryptedMsg = mac.verifyMAC(msg)
        aes = AES256(sessionKey)
        return aes.decrypt(encryptedMsg)


if __name__ == "__main__":
    mode = sys.argv[1]
    address = sys.argv[2]
    port = int(sys.argv[3])

    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bob_socket.bind((address, port))
    bob_socket.listen(1)
    (malloryConnection, malloryAddress) = bob_socket.accept()

    initMsg = malloryConnection.recv(4096)
    sessionKey = processSessionKey(initMsg, 'Alice', 'Bob')

    try:
        seqNumber = 1
        while True:
            msg = malloryConnection.recv(4096)
            if not msg: break
            parsedMsg = json.loads(processMessage(mode, msg, sessionKey))
            print parsedMsg['msg']
            if (seqNumber != parsedMsg['seqNumber']):
                print("\nSequence number does not match the expected value.")
                print("Communication lines have been compromised. Shutting down!")
                break
            seqNumber += 1

    except socket.error as e:
        print("Communication socket closed.")
    except Exception:
        print("Communication lines have been compromised. Shutting down!")
bob_socket.shutdown(socket.SHUT_RDWR)
bob_socket.close()