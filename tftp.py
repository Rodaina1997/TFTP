import sys
import os
import enum

import socket
from sys import argv

TERMINATING_DATA_LENGTH = 512
true=1
current_block=1

error_type = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}


class TftpProcessor():
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        rrq = 1
        wrq = 2
        data = 3
        ack = 4
        error = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.current_block = 1
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)


    def _parse_udp_packet(self, packet_bytes):

        global opcode
        opcode=packet_bytes[1]
        while true:

            if opcode ==4:  #acknowledgement

                print('Acknowledgement packet received')
                break
            elif opcode ==5:
                errorcode=packet_bytes[3]
                print('error packet received')
                print(error_type[errorcode])
                break

            elif opcode==3:

                print('data packet received')
                break
        return packet_bytes



    def _do_some_logic(self, input_packet):

        response=bytearray()
        if opcode==4:
            response=TftpProcessor.data_packet(input_packet)
            self.current_block += 1
        elif opcode==3:
           response=TftpProcessor.ack_packet(object,input_packet)
           TftpProcessor.process_downloaded_file(object,input_packet)


        return response

    def data_packet(acket_bytes):
        data_packet = bytearray()
        data_packet.append(0)
        data_packet.append(3)
        data_packet.append(0)
        data_packet.append(current_block)
        # info=[chunk_bytes[i:i + 512] for i in range(0, len(chunk_bytes), 512)]
        # for j in chunk_bytes:
        # data_packet += j
        # data_packet += bytearray(j)
        # data_packet+=bytearray(info)
        # data_packet += chunk_bytes
        # self.packet_buffer.append(data_packet)
        data_packet += bytearray(chunk_bytes)
        x = list(data_packet)
        print(f"Request {x}")
        return data_packet




    def process_downloaded_file(self,input_packet):
        file=open("rodaina.txt","wb")
        data=input_packet[4:]
        print(f"data is: {data}")
        file.write(data)

        pass




    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0


    def ack_packet(self,data):

        object = TftpProcessor()
        blockno1=data[2]
        blockno2=data[3]
        ack=bytearray(4)
        ack[0]=0
        ack[1]=4
        ack[2]=blockno1
        ack[3]=blockno2

        return ack

    def request_file(self,file_name):
        global rrq
        rrq = bytearray()
        rrq.append(0)
        rrq.append(1)
        #filename = b'rodaina'
        filename = file_name.encode('ascii', 'ignore')
        rrq = rrq + filename
        rrq.append(0)
        mode = 'octet'
        mode_byte = mode.encode('ascii', 'ignore')
        #rrq = rrq+mode_byte
        rrq.append(0)
        x = list(rrq)
        print(f"Request {x}")


    def upload_file(self,file_name):

        global wrq
        wrq = bytearray()
        wrq.append(0)
        wrq.append(2)
        #filename=b'rodaina'
        filename = file_name.encode('ascii', 'ignore')
        wrq = wrq + filename
        wrq.append(0)
        mode = 'octet'
        mode_byte = mode.encode('ascii', 'ignore')
        wrq = wrq + mode_byte
        wrq.append(0)
        x = list(wrq)
        print(f"Request {x}")






def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():

    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    ip_address = get_arg(1, "127.0.0.1")
    global operation
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "hello.txt")

    #python_file, ip_address, operation, file_name = argv



    global chunk_bytes
    with open("a.txt", 'rb') as infile:
        while True:

            # Read 512 byte chunks
            chunk = infile.read(512)
            if not chunk: break

            chunk_bytes = bytearray(chunk)


    # Create a UDP socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 69)
    object = TftpProcessor()


    if operation == 'pull':
        TftpProcessor.request_file(object,file_name)
        request = rrq


    else:
        TftpProcessor.upload_file(object,file_name)
        request = wrq


        # Send data
    sent = sock.sendto(request, server_address)
    #file = open(file_name, "rb")

    while true:

            # Receive response
        print('waiting to receive')
        data, server = sock.recvfrom(4096)
        d = dict(toks.split(":") for toks in data.decode("ascii").split(";") if toks)
        print('received {!r}'.format(data))


        if len(data) < TERMINATING_DATA_LENGTH:

            break




    TftpProcessor.process_udp_packet(object, data, server)
    sent = sock.sendto(TftpProcessor.get_next_output_packet(object), server)
    print('closing socket')
    sock.close()
    pass

if __name__ == "__main__":
    main()
