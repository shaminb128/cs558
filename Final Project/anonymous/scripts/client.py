import socket

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = "node1.finalprojecttest.usc558l"

port = 8888

# connection to hostname on the port.
s.connect((host, port))                               

s.send("1")
print s.recv(1024)
s.close()
