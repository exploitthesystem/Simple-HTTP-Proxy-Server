# Simple-HTTP-Proxy-Server
A proxy server that filters HTTP content based on results from an online malware hash registry.

# Author:  Marko Ljubicic
# Project: PA1 - HTTP Web Proxy Server
# File:    HttpProxyServer.py

The program was written in Python 3.x. It is important that "python3"
is used from the command line instead of "python." The latter version
will not recognize some libraries that are required to run the program.
The server does support multi-client access.

The web proxy has been successfully tested with cURL and Telnet.
Brief but successful testing using Firefox 15.0 with modified parameter
settings, as recommended in the assignment instructions PDF, has also
been performed.

The following commands/clients have been tested:

curl --proxy1.0 localhost:[port] [URL]
telnet [hostname] [port]

Run server:

python3 HttpProxyServer.py [port]

Example request:

curl --proxy1.0 localhost:8888 http://www.cs.utah.edu/~kobus/simple.html

Response:

<!DOCTYPE html>
<html>
<body>

<h1>Real Simple</h1>

</body>
</html>
