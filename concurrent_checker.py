#!/usr/bin/python

import http.client
import sys
import random
import os
import time
import unittest
if len(sys.argv) < 6:
    sys.stderr.write('Usage: %s <ip> <port> <#trials>\
            <#writes and reads per trial>\
            <max # bytes to write at a time> <#connections> \n' % (sys.argv[0]))
    sys.exit(1)

serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
numTrials = int(sys.argv[3])
numWritesReads = int(sys.argv[4])
#numBytes = int(sys.argv[5])
numConnections = int(sys.argv[5])

if numConnections < numWritesReads:
    sys.stderr.write('<#connections> should be greater than or equal to <#writes and reads per trial>\n')
    sys.exit(1)


RECV_TOTAL_TIMEOUT = 100
RECV_EACH_TIMEOUT = 0.05
test = unittest.TestCase

for cnum in range(numTrials):

    pid = os.fork()

    if pid == 0: #child
        time.sleep(0.005)
        client_lst = []
        for i in range(numConnections):
            time.sleep(0.000005)
            h = http.client.HTTPConnection(serverHost, serverPort)
            time.sleep(0.000005)
            client_lst.append(h)

        client_subSet = []
        client_subSet = random.sample(client_lst, numConnections)

        response_lst = []
        for j in range(numWritesReads):
            #client_subSet[j].request("GET", "/index.html")
            if j % 2 == 0:
                client_subSet[j].request("GET","/images/liso_header.png")
            else:
                client_subSet[j].request("GET","/index.html")
            time.sleep(0.00007)
            r1 = client_subSet[j].getresponse()
            response_lst.append(r1)
        for j in range(numWritesReads):
            time.sleep(0.00001)
            print(response_lst[j].getheaders())
        sys.exit(1)
