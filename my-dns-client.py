# Luis Ferrufino
# CS 455-003
# PA#1
# G#00997076

from socket import *
import random
import time
import sys
serverName = '8.8.8.8'
serverPort = 53
clientSocket = socket(AF_INET, SOCK_DGRAM)

#PHASE 1: Prepare the query:
print("-------------------------------------------------------")
print("Preparing the query...")
inquiry = sys.argv[1]
labels = inquiry.split('.')
question = ""

for i in labels:
    
    question += chr(len(i))
    question +=  i
question += '\0' #the 'zero-length' octet
question += '\0' + chr(1) # QTYPE field (set to A)
question += '\0' + chr(1) # QCLASS field (set to IN)
identif = random.randrange(0, 65535)
restOfHeader = 0x01000001000000000000
query = (identif).to_bytes(2, 'big') + (restOfHeader).to_bytes(10, 'big') + bytes(question, 'ascii')
#PHASE 2: Send the query:
print("Sending the query...")
#clientSocket.sendto(message.encode(), (serverName, serverPort
clientSocket.sendto(query, (serverName, serverPort))

#PHASE 3: Receive the respnse:
#timeOut = 0
#startTime = time.time()
print("Receiving the response...")
success = False
numTries = 0
clientSocket.settimeout(5)

while ( success == False and numTries < 3 ):

    success = True
    try:

        dnsReply, serverAddress = clientSocket.recvfrom(2048)
    except OSError:
    #except socket.timeout:
        print('Timed out on try number ' + str(numTries + 1))
        success = False
    numTries += 1

if ( success == False ):

    print("Sorry, we failed to get receive the response")
    quit()
#PHASE 4: Parse response:
print("Parsing the response...\n")
print("header.ID = " + str( int.from_bytes(dnsReply[:2], "big") ))
print("header.QR = " + str( ( dnsReply[2] & 0x80 ) >> 7 ) )
print("header.OPCODE = " + str( ( dnsReply[2] & 0x78 ) >> 3 ) )
print("header.AA = " + str( ( dnsReply[2] & 0x04 ) >> 2 ) )
print("header.TC = " + str( ( dnsReply[2] & 0x02 ) >> 1 ) )
print("header.RD = " + str( dnsReply[2] & 0x10 ) )
print("header.RA = " + str( ( dnsReply[3] & 0x80 ) >> 7 ) )
print("header.Z = " + str( ( dnsReply[3] & 0x70 ) >> 4 ) )
print("header.RCODE = " + str( dnsReply[3] & 0x0f ) )
print("header.QDCOUNT = " + str( int.from_bytes(dnsReply[4:6], "big") ) )
anCount = int.from_bytes(dnsReply[6:8], "big")
nsCount = int.from_bytes(dnsReply[8:10], "big")
arCount = int.from_bytes(dnsReply[10:12], "big")
print("header.ANCOUNT = " + str( anCount ) )
print("header.NSCOUNT = " + str( nsCount ) )
print("header.ARCOUNT = " + str( arCount ) )

print("")
#we're going to have to loop through labels in the QNAME field:
i = 12
print("question.QNAME = ", end='')
while dnsReply[i] != 0:
    size = dnsReply[i]
    #print( str( int.from_bytes(dnsReply[i + 1:i + size + 1], "big") ), end='' )
    print( (dnsReply[i + 1:i + size + 1]).decode("ascii"), end='' )
    i = i + size + 1

    if dnsReply[i] != 0:
        print('.', end='')
print("")
i += 1
print("question.QTYPE = " + str( int.from_bytes(dnsReply[i:i + 2], "big") ) )
print("question.QCLASS = " + str( int.from_bytes(dnsReply[i + 2:i + 4], "big") ) )

#now we're going to print the fields from the resource record sections:
i += 4

for j in range(0, anCount + nsCount + arCount):

    print("")
    print("answer.NAME =", str( int.from_bytes(dnsReply[i:i + 2], "big") ) )
    print("answer.TYPE =", str( int.from_bytes(dnsReply[i + 2: i + 4], "big") ) )
    print("answer.CLASS =", str( int.from_bytes(dnsReply[i + 4: i + 6], "big") ) )
    print("answer.TTL =", str( int.from_bytes(dnsReply[i + 6: i + 10], "big") ) )
    print("answer.RDLENGTH =", str( int.from_bytes(dnsReply[i + 10: i + 12], "big") ) )
    print("answer.RDATA = ", str( dnsReply[i + 12] ), ".", str( dnsReply[i + 13] ), ".", str( dnsReply[i + 14]),
        ".", str( dnsReply[i + 15] ), sep = '')
    i = i + 16
print("-------------------------------------------------------")
clientSocket.close()
