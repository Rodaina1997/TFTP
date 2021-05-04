# TFTP
It is a Trivial file transfer protcol,
A project to simulate the TFTP client in python,
The protocol operation occurs in two steps 1) Connection establishment 2) Data transfer
> Connection establishment
Connections are initiated by clients by sending either a read request (RRQ) to download files from the server or sending a write request (WRQ) to upload files to the server. Those requests will be sent to the default server port which is 69.
After receiving a request, the server makes a new UDP socket for each client. Then checks if the request can be fulfilled and handles the required errors. Then using this new socket, the server will send the reply (ACK/ERR) to the client.
The positive reply for an RRQ is the first data block in the requested file (blk #1).
For a WRQ, the positive reply from the server in an ACK message with a block number 0, (blk #0).
Negative replies (if an error occurs), will be an ERR packet.
You're asked to handle only two error cases 
File existence on server
The client sending data to the main socket on port 69
Here are two examples of connection initiation
> Host  A  sends  a  "RRQ"  to  SERVER  with  source= A's PORT, destination= MAIN_SERVER_PORT.
< SERVER sends a "DATA" (with block number= 1) to host A with source= SERVER's NEW_SOCKET_PORT, destination= A's PORT.
>> Host A sends  a  "WRQ"  to  SERVER  with  source=  A's  PORT, destination= MAIN_SERVER_PORT.
<< SERVER  sends  a "ACK" (with block number= 0) to host A with source= SERVERS's NEW_SOCKET_PORT, destination= A's PORT.
> Data Transfer
Data transfer happens between two entities, one of them sends data and the other sends an ACK for each data packet sent. 
