import sys
import threading 
import socket

HEX_FILTER = ''.join([len(repr(chr(i))) == 3 and chr(i) or '.' for i in range(256)])

def hexadump(src, show=True, length=16):
    if isinstance(src, bytes):
        src = src.decode()
    
    result = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])

        printables = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hex_width = 3 * length

        result.append(f'{i:04X} {hexa:<{hex_width}} {printables}')

    if show:
        for line in result:
            print(line)
    else:
        return result

def receive_from(connection):
    buffer = b""

    # Since receiving packets takes time await 5 sec
    # connection.timeout(5)

    # Sometimes it may not respond with anything so exception could 
    # be generated
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    
    return buffer

# Handlers used to modify incoming buffer
# as well as outgoing buffer
def request_handler(buffer):
    return buffer

def response_handler(buffer):
    return buffer

# Sometimes some server threads require as to 
# receive some data first before allowing incoming packets
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_host, remote_port))
        print(f'[<>] Connection established with {remote_host}:{remote_port}')
    except Exception as e:
        print(f"[!] Failed to connect to remote host: {e}")
        return

    # Make a buffer from received initial packets
    if receive_first:
        remote_buffer = receive_from(remote_socket)
    
    # Optionally twist and play with the packets in response_handler fn
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print('[<==] Sending %d bytes to localhost' %len(remote_buffer))
        client_socket.send(remote_buffer)
    
    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print('[~] Sending %d bytes to remotehost' %len(local_buffer))
            hexadump(local_buffer)
            local_buffer = request_handler(local_buffer)

            remote_socket.send(local_buffer)
            print('[<==] Sent to remote host')

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print('[~] Sending %d bytes to localhost' %len(remote_buffer))
            hexadump(remote_buffer)
            remote_buffer = response_handler(remote_buffer)

            client_socket.send(remote_buffer)
            print('[<==] Sent to localhost')
        
        # If none endpoints are sending packets break out of the loop
        if not len(remote_buffer) or not len(local_buffer):
            client_socket.close()
            remote_socket.close()
            print('[!!!] No More Data. Connections Closed.')
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host, local_port))
        server.listen(5)
        print("Proxy is listening on %s:%d" %(local_host, local_port))
    except Exception as e:
        print('[!] Exception Caught')
        print('[!!] Can\'t bind %s and %d' %(local_host, local_port))
        print('[!!!] Port maybe in use.')
        sys.exit(0)
    
    while True:
        client_socket, addr = server.accept()
        print('[->] Received connection from %s:%d' %(addr[0], addr[1]))
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def main():
    if len(sys.argv[1:]) != 5:
        print('[!] Usage: sudo python3 proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]')
        print('Example Usage: sudo python3 proxy.py 127.0.0.1 21 202.23.43.XX 21 True')
        return

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = False

    if 'True' in sys.argv[5]:
        receive_first = True

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)    

if __name__ == '__main__':
    main()
        