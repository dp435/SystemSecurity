import sys
import socket
import json

if __name__ == "__main__":
    mode = sys.argv[1]
    address = sys.argv[2]
    port = int(sys.argv[3])
    bobAddress = sys.argv[4]
    bobPort = int(sys.argv[5])

    aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    aliceSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    aliceSocket.bind((address, port))
    aliceSocket.listen(1)
    (aliceConnection, aliceAddress) = aliceSocket.accept()

    bobSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bobSocket.connect((bobAddress, bobPort))

    msg = aliceConnection.recv(4096)
    bobSocket.send(msg)

    try:
        seqNumber = 1
        msgArray = []
        while True:
            msg = aliceConnection.recv(4096)
            if not msg: break
            if (mode == '-n'):
                parsedMsg = json.loads(msg)
                print parsedMsg['msg']
                action = raw_input("\nEnter action:\n\n\t[d]elete\n\t[r]eplay\n\t[m]odify\n\t[s]end unaltered\n")
                if (action == 'd'):
                    continue
                elif(action == 'm'):
                    fakeMsg = raw_input("Enter msg:")
                    parsedMsg['msg'] = fakeMsg
                    parsedMsg['seqNumber'] = seqNumber
                    msg = json.dumps(parsedMsg)
                bobSocket.send(msg)
            elif (mode == '-e'):
                parsedMsg = json.loads(msg)
                print("ciphertext: " + parsedMsg['msg'])
                action = raw_input("\nEnter action:\n\n\t[d]elete\n\t[r]eplay\n\t[m]odify\n\t[s]end unaltered\n")
                bobSocket.send(msg)
            elif (mode == '-m'):
                parsedMAC = json.loads(msg)
                print("tag: " + parsedMAC['mac'])
                parsedMsg = json.loads(parsedMAC['msg'])
                print("message: " + parsedMsg['msg'])
                action = raw_input("\nEnter action:\n\n\t[d]elete\n\t[r]eplay\n\t[m]odify\n\t[s]end unaltered\n")
                
                if (action == 'r' and len(msgArray) == 0):
                    print "No messages to replay. Please select another action."
                    action = raw_input("\nEnter action:\n\n\t[d]elete\n\t[m]odify\n\t[s]end unaltered\n")

                if (action == 'r' and len(msgArray) > 0):
                    msg = msgArray[0]
                    print "Replaying:\n"
                    parsedMAC = json.loads(msg)
                    print("tag: " + parsedMAC['mac'])
                    parsedMsg = json.loads(parsedMAC['msg'])
                    print("message: " + parsedMsg['msg'])
                elif (action == 'd'):
                    continue
                elif(action == 'm'):
                    fakeMsg = raw_input("Enter msg:")
                    parsedMsg['msg'] = fakeMsg
                    parsedMsg['seqNumber'] = seqNumber
                    parsedMAC['msg'] = json.dumps(parsedMsg)
                    msg = json.dumps(parsedMAC)
                if (len(msgArray) == 0):
                    msgArray.append(msg)
                else:
                    msgArray[0] = msg
                bobSocket.send(msg)
            elif (mode == '-em'):
                parsedMsg = json.loads(msg)
                print("tag: " + parsedMsg['mac'])
                encryptedMsg = parsedMsg['msg']
                parsedEncryptedMsg = json.loads(encryptedMsg)
                print("ciphertext: " + parsedEncryptedMsg['msg'])
                action = raw_input("\nEnter action:\n\n\t[d]elete\n\t[r]eplay\n\t[m]odify\n\t[s]end unaltered\n")
                bobSocket.send(msg)
            seqNumber += 1
    except socket.error as e:
        aliceSocket.shutdown(socket.SHUT_RDWR)
        aliceSocket.close()
        print("Connection terminated by client.")