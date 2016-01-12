import socket
import sys
 
HOST=raw_input("Enter HOST name:-")
#HOST="node1.finalprojecttest.usc558l"

PORT = 5001 # Arbitrary non-privileged port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print 'Socket created'
 
try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
     
print 'Socket bind complete'
 
s.listen(10)
print 'Listening for Requests'

while 1:
    conn, addr = s.accept()
    request=conn.recv(2000)
    if ',' in request:
	file_to_write=open('../Database/data.txt','a')
	file_to_write.write(request+"\n")
	file_to_write.close()
    else:
	request_completed=0
	file_to_read=open('../Database/data.txt','r')
	for line in file_to_read:
		key,value=line.split(',')
		if key.strip()==request.strip():
			conn.send(value.strip())
			print key,value
	     		request_completed=1
	if request_completed==0:
		conn.send('0')
			

s.close()


