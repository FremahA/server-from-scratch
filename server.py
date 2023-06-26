import socket

HOST, PORT = '', 8888

listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket instance
listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listen_socket.bind((HOST, PORT)) # bind to address
listen_socket.listen(1) # listen for connections
print('Serving HTTP on port {PORT} ...')
while True:
    client_connection, client_address = listen_socket.accept()  #accept and return new socket and bind address
    print("Fremah")
    request_data = client_connection.recv(1024)  #returns bytes. argument is maximum amount of data to be received
    print(request_data.decode('utf-8')) #decode to avoid problems with data

    http_response = b"""\
HTTP/1.1 200 OK

Hello, World, I just created a Web Server...!
"""
    print(http_response)
    client_connection.sendall(http_response) # send response
    client_connection.close() # close connection
    