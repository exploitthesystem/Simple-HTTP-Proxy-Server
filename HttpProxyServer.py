# Author:  Marko Ljubicic
# Project: PA1 - HTTP Web Proxy Server
# File:    HttpProxyServer.py
#
# Description:
#              An HTTP web proxy that can process
#              GET requests from multiple clients.

import sys
import errno
import socket
import re
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPResponse
from urllib.parse import urlparse
from multiprocessing import Process
from io import StringIO, BytesIO

# Verifies that at least two arguments are provided by command line (the host address and port number).
if len(sys.argv) <= 1: 
    print('Usage: "python S.py port"\n[port : It is the port of the Proxy Server')
    sys.exit(2)

# Server socket created, bound and starting to listen
serverPort = int(sys.argv[1]) # sys.argv[1] is the port number entered by the user.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket.socket function creates a socket.
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind(('', serverPort)) # Bind the server socket to the listening port.
serverSocket.listen(1)
print('Waiting for client connection...\n')

# This helper class is used to parse an HTTP request message.
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text.encode('utf-8', 'surrogateescape'))
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message
        
# Start new process to parse client message and send it out to web server if it's valid.
def processConnection(connectionSocket, addr):
    message = recvData(connectionSocket)

    message = remove_backspace(message)
    request = HTTPRequest(message)
    
    # Send error message to client if the request isn't properly formatted.
    if request.error_code != None:
        response = ('HTTP/1.0 ' + str(request.error_code.value) + ' ' + request.error_code.phrase
                 + ' : ' + request.error_message + '\r\n\r\n')
        connectionSocket.send(response.encode())
        connectionSocket.close()
        sys.exit(0)

    # Send error message to client if the HTTP method is anything other than GET.
    if request.command != None and request.command.upper() != 'GET':
        response = 'HTTP/1.0 501 Not Implemented\r\n\r\n'        
        connectionSocket.send(response.encode())
        connectionSocket.close()
        sys.exit(0)

    # Parse the URL to extract path info and a port number if present.
    parsedURL = urlparse(request.path)

    # The hostname was either provided in the URL or as a header.
    hostname = ''
    if parsedURL.hostname != None:
        hostname = parsedURL.hostname
    else:
        hostname = request.headers['host']
    
    # Reconstitute the parsed GET request with the Connection: close header included.
    requestLine = request.command.upper() + ' ' + parsedURL.path + ' ' + request.request_version
    message_parts = [ requestLine ]

    # Include a Connection: close header in the HTTP request.
    request.headers['Connection'] = 'close'
    
    for name, value in sorted(request.headers.items()): # Append all headers to the request line.
        message_parts.append('%s: %s' % (name, value))
    message_parts.append('\r\n')
    message = '\r\n'.join(message_parts)

    # If port number was specified, assign it to variable, else assign port 80 as default.
    if parsedURL.port != None:
        port = parsedURL.port
    else:
        port = 80

    # Create socket connection to remote web server.
    webServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    webServerSocket.connect((hostname, port))
    webServerSocket.send(message.encode())

    serverResponse = recvData(webServerSocket)

    data = serverResponse.split('\r\n\r\n')[1]

    teamCymruSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    teamCymruSocket.connect(('hash.cymru.com', 43))

    # Send hash to the Team Cyrmu Malware Hash Registry
    h = hashlib.md5((data).encode('utf-8', 'surrogateescape')).hexdigest()
    teamCymruSocket.send((h + '\r\n').encode())
    teamCymruResponse = teamCymruSocket.recv(1024).decode()

    # If the hash was not found in the registry, send the message along to the client.
    if 'NO_DATA' in teamCymruResponse:
        connectionSocket.send(serverResponse.encode('utf-8', 'surrogateescape'))
    else: # Else send an HTML warning page.
        s = ('<!DOCTYPE html>\r\n' +
                  '<html>\r\n' +
                  '<body>\r\n' +

                  '\r\n<h1>WARNING: Malware Detected</h1>\r\n' +

                  '\r\n</body>\r\n' +
                  '</html>\r\n\r\n')

        connectionSocket.send(('HTTP/1.0 403 Forbidden\r\n' +
                  'Content-Length: ' + str(len(s.encode('utf-8'))) + '\r\n\r\n'
                  '<!DOCTYPE html>\r\n' +
                  '<html>\r\n' +
                  '<body>\r\n' +

                  '\r\n<h1>WARNING: Malware Detected</h1>\r\n' +

                  '\r\n</body>\r\n' +
                  '</html>\r\n\r\n').encode())
    
    print('Response forwarded to: ', addr)
    
    connectionSocket.close()
    sys.exit(0)
    
def recvData(connectionSocket):
    End = '\r\n\r\n'
    totalData = []; data = ''
    body = ''
    while True:
        data = connectionSocket.recv(2048).decode('utf-8', 'surrogateescape')
        if End in data:
            totalData.append(data)
            if 'Content-Length' in data:
                body = connectionSocket.recv(4096).decode('utf-8', 'surrogateescape')
                totalData.append(body)
            break
        totalData.append(data)
        if len(totalData) > 1:
            lastPair = totalData[-2] + totalData[-1]
            if End in lastPair:
                totalData[-2] = lastPair[:lastPair.find(End)]
                totalData.pop()
                break
    return ''.join(totalData)

# Removes (invisible) backspace characters that are passed along with a request.
# These corrupt the message when using a Telnet client for example.
def remove_backspace(s):
    while True:
        # if you find a character followed by a backspace, remove both
        t = re.sub('.\b', '', s, count=1)
        if len(s) == len(t):
            # remove any backspaces from start of string
            return re.sub('\b+', '', t)
        s = t
        
if __name__ == '__main__':
    # Receive and process incoming connection.
    while True:
        try:
            connectionSocket, addr = serverSocket.accept() # Accept connection and store socket and the client address.
            print('Connection received from: ', addr)
            p = Process(target=processConnection, args=(connectionSocket, addr,))
            p.start()
        except socket.error as err:
            print('A socket error occurred.')
