import socket

""" DeviceHandler class to handle incoming data stream """
class DeviceHandler:

    def __init__(self, host, server_port, filepath):
        """ constructor class """
        self.host_addr = (host, int(server_port))
        self.filepath = filepath
        self.server_socket = self.open_port()
        self.listen_for_data_stream()

    def open_port(self):
        """ open port """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(self.host_addr)
        return server_socket

    def close_port(self):
        """ close port """
        self.server_socket.close()

    def listen_for_data_stream(self):
        """ listen for an incoming client """
        # loop forever
        while True:

            self.server_socket.listen(5)
            print("Listening for client")

            # when an incoming connection occurs
            conn, address = self.server_socket.accept()
            print("Connected to client, with address {}".format(address))

            while True:

                output = conn.recv(2048).decode("utf-8")

                # if stream finished
                if output.strip() == "stop_stream":
                    print("connection closed")
                    conn.send(bytes("dc_ack", "utf-8"))
                    conn.close()
                    break

                # store output in a local file
                elif output:
                    print("Data stream received")
                    f = open(self.filepath, "a")
                    f.write(output)
                    conn.send(bytes("ack", "utf-8"))
                    f.close()


server = DeviceHandler('localhost', 1234, "./message_file")