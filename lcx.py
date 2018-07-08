import sys
import ipaddress
import asyncio
import socket
import json
import struct
import random
import re
import string
import hashlib
import time

def usage():
    """Print the usage."""
    print('usage: python/python3 lcx.py [-m MODE] [-r IP:PORT] [-p PORT]')
    print('                             [-u USER:PWD] [-l IP:PORT] [-h]\n')
    print('lcx is a tool for Networt Penetration.')
    print('Options:')
    print('  -m MODE=listen/slave   slave is the local server machine')
    print('                         listen is the proxy server\n')
    print('MODE=slave')
    print('  -r IP:PORT             remote connect to IP:PORT, the remote')
    print('                         listen machine/proxy machine')
    print('  -u USER:PWD            appoint the username and the password')
    print('  -p PORT                appoint remote listen machine the port')
    print('                         to listen for the remote client')
    print('  -l IP:PORT             remote connect to IP:PORT, the local')
    print('                         server machine\n')
    print('MODE=listen')
    print('  -p PORT                appoint remote listen machine the port')
    print('                         to listen for the remote client, multi-')
    print('                         ports use \',\' to split')
    print('  -u USER:PWD            appoint the username and the password,')
    print('                         multiple users use \',\' to split\n')
    print('optional arguments')
    print('  -h                     help')
    sys.exit()


def argv_process():
    """Process the different options."""
    # Help
    if sys.argv[1] == '-h':
        usage()
    args = {}
    for i in range(1, len(sys.argv)-1, 2):
        args[sys.argv[i]] = sys.argv[i+1]
    # Listen mode
    if args.get('-m') == 'listen':
        if len(sys.argv) != 7 or args.get('-p') is None or args.get('-u') is None:
            usage()
        # -p
        if args.get('-p').isdigit() and 0 <= int(args.get('-p')) <= 65535:
            port = int(args.get('-p'))
        else:
            usage()
        # -u
        if re.match(r'^(\w+:\w+,)*\w+:\w+$', args.get('-u')) is not None:
            users = {}
            for user in args.get('-u').split(','):
                username = user.split(':')[0]
                pwd = user.split(':')[1]
                users[username] = pwd
        else:
            usage()
        proxy_server = ProxyServer(port, users)
        proxy_server.listen()

    # Slave mode
    elif args.get('-m') == 'slave':
        if (len(sys.argv) != 11 or args.get('-r') is None or args.get('-u') is None or
            args.get('-p') is None or args.get('-l') is None):
            usage()
        # -r
        if re.match(r'^[^:]+:\d+$', args.get('-r')) is not None:
            ip = args.get('-r').split(':')[0]
            try:
                ipaddress.ip_address(ip)
            except:
                usage()
            if args.get('-r').split(':')[1].isdigit and 0 <= int(args.get('-r').split(':')[1]) <= 65535:
                port = int(args.get('-r').split(':')[1])
            else:
                usage()
            remote_addr = (ip, port)
        else:
            usage()
        # -u
        if re.match(r'^\w+:\w+$', args.get('-u')) is not None:
            user = (args.get('-u').split(':')[0], args.get('-u').split(':')[1])
        else:
            usage()
        # -l
        if re.match(r'^[^:]+:\d+$', args.get('-l')) is not None:
            ip = args.get('-l').split(':')[0]
            try:
                ipaddress.ip_address(ip)
            except:
                usage()
            if args.get('-l').split(':')[1].isdigit and 0 <= int(args.get('-l').split(':')[1]) <= 65535:
                port = int(args.get('-l').split(':')[1])
            else:
                usage()
            local_addr = (ip, port)
        else:
            usage()
        # -p
        if re.match(r'^(\d+,)*\d+$', args.get('-p')):
            ports = []
            for port in args.get('-p').split(','):
                if 0 <= int(port) <= 65535:
                    ports.append(int(port))
                else:
                    usage()
        else:
            usage()
        slave_machine = SlaveMachine(remote_addr, user, ports, local_addr)
        slave_machine.slave()
    else:
        usage()


class Vividict(dict):
    """ Self-Defined Nesting Dict Class"""
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value


class Lcx(object):
    """ A tool for port transmit. The BaseProtocol of ProxyServer and SlaveMachine.

        The format of the lcx Transport Protocol as follows.
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Message-Length   2 bytes    | Command 1 byte| Variable...
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Specific command as follows. (The part without Message-Length and Command)
        1. chap:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                  Salt-Value        32 bytes                   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Name-Length 1 | Username Variable...
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                  Hash-Value        32 bytes                   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+
            | Result 1 byte |
            +-+-+-+-+-+-+-+-+
        2. bind
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     Request-ID    2 bytes     |     Listen Port   2 bytes     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     Request-ID    2 bytes     | Result 1 byte | Listen port   2 bytes     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        3. connect
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     Request-ID    2 bytes     |     Listen Port   2 bytes     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     Request-ID    2 bytes     | Result 1 byte | Connection-ID  2 bytes    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        4. data
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Connection-ID    2 bytes    |     Data-Length   2 bytes     | Data...
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        5. disconnect
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Connection-ID    2 bytes    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        6. heartbeat
    """
    loop = asyncio.get_event_loop()
    buf_size = 1024
    chap_salt = 1
    chap_name = 2
    chap_hash = 3
    chap_result = 4
    bind_request = 5
    bind_response = 6
    connect_request = 7
    connect_response = 8
    data = 9
    disconnect = 10
    heartbeat = 11

    def __init__(self):
        pass

    async def recv_data(self, reader):
        """ Runs for recving data, firstly receive the header."""
        recv = await reader.read(3)
        if not recv:
            return None
        header = struct.unpack('!HB', recv)
        command = header[1]

        if command == self.chap_salt:
            recv = await reader.read(32)
            if not recv:
                return None
            chap_salt = recv.decode('utf-8')
            return ('chap-salt', chap_salt)

        elif command == self.chap_name:
            recv = await reader.read(1)
            if not recv:
                return None
            body = struct.unpack('!B', recv)
            name_length = body[0]
            recv = await reader.read(name_length)
            if not recv:
                return None
            chap_name = recv.decode('utf-8')
            return ('chap-name', chap_name)

        elif command == self.chap_hash:
            recv = await reader.read(32)
            if not recv:
                return None
            chap_hash = recv.decode('utf-8')
            return ('chap-hash', chap_hash)

        elif command == self.chap_result:
            recv = await reader.read(1)
            if not recv:
                return None
            body = struct.unpack('!B', recv)
            chap_result = body[0]
            return ('chap-result', chap_result)

        elif command == self.bind_request:
            recv = await reader.read(4)
            if not recv:
                return None
            body = struct.unpack('!HH', recv)
            request_id = body[0]
            listen_port = body[1]
            return ('bind-request', request_id, listen_port)

        elif command == self.bind_response:
            recv = await reader.read(5)
            if not recv:
                return None
            body = struct.unpack('!HBH', recv)
            request_id = body[0]
            result = body[1]
            listen_port = body[2]
            return ('bind-response', request_id, result, listen_port)

        elif command == self.connect_request:
            recv = await reader.read(4)
            if not recv:
                return None
            body = struct.unpack('!HH', recv)
            request_id = body[0]
            listen_port = body[1]
            return ('connect-request', request_id, listen_port)

        elif command == self.connect_response:
            recv = await reader.read(5)
            if not recv:
                return None
            body = struct.unpack('!HBH', recv)
            request_id = body[0]
            result = body[1]
            connection_id = body[2]
            return ('connect-response', request_id, result, connection_id)

        elif command == self.data:
            recv = await reader.read(4)
            if not recv:
                return None
            body = struct.unpack('!HH', recv)
            connection_id = body[0]
            data_length = body[1]
            recv = await reader.read(data_length)
            if not recv:
                return None
            return ('data', connection_id, recv)

        elif command == self.disconnect:
            recv = await reader.read(2)
            if not recv:
                return None
            body = struct.unpack('!H', recv)
            connection_id = body[0]
            return ('disconnect', connection_id)

        elif command == self.heartbeat:
            return ('heartbeat')

    async def send_data(self, writer, command, args):
        """ Use socket to send data, firstly send the header.

            Args:
                writer: the StreamWriter object
                command: protocol command, decide the format
                args: the list of the corresponding arguments of command
        """
        if command == self.chap_salt:
            header = struct.pack('!HB', 35, command)
            writer.write(header)
            writer.write(args.encode('utf-8'))

        elif command == self.chap_name:
            header = struct.pack('!HBB', 4+len(args), command, len(args))
            writer.write(header)
            writer.write(args.encode('utf-8'))

        elif command == self.chap_hash:
            header = struct.pack('!HB', 35, command)
            writer.write(header)
            writer.write(args.encode('utf-8'))

        elif command == self.chap_result:
            header = struct.pack('!HBB', 4, command, args)
            writer.write(header)

        elif command == self.bind_request:
            send = struct.pack('!HBHH', 7, command, args[0], args[1])
            writer.write(send)

        elif command == self.bind_response:
            send = struct.pack('!HBHBH', 8, command, args[0], args[1], args[2])
            writer.write(send)

        elif command == self.connect_request:
            send = struct.pack('!HBHH', 7, command, args[0], args[1])
            writer.write(send)

        elif command == self.connect_response:
            send = struct.pack('!HBHBH', 8, command, args[0], args[1], args[2])
            writer.write(send)

        elif command == self.data:
            header = struct.pack('!HBHH', 7+len(args[1]), command, args[0], len(args[1]))
            writer.write(header)
            writer.write(args[1])

        elif command == self.disconnect:
            send = struct.pack('!HBH', 5, command, args)
            writer.write(send)

        elif command == self.heartbeat:
            send = struct.pack('!HB', 3, command)
            writer.write(send)


class ProxyServer(Lcx):
    """ Listen to the slave machine, and send CHAP challenge to it, then
        receive the bind-request from slave machine. When a new connect
        from remote client, send the connect-request to the slave machine.

    Attributes:
        transmit_port: Listen port for slave.
        users: A dict which is the database to store username and password.
        connect_ports: A dict storing ports requested by slave and writers.
        client_writers: A dict storing slave and the dict of its connection-id and client_writer.
        cur_request: current request_id
        request: A dict store request_id and connection_id
        ports: A dict judging whether the port is being occupied or not.
    """

    def __init__(self, port, users):
        """Inits ProxyServer with port and users."""
        self.transmit_port = port
        self.users = users
        self.connect_ports = {}
        self.client_writers = Vividict()
        self.cur_request = -1
        self.request = {}
        self.ports = {}

    async def chap_server(self, reader, writer):
        """ CHAP Authentication sender.

            salt is 32 length digit and alpha letter random string,
            hash is 32 length md5 value, use salt and password to caculate.
        """
        salt = ''.join(random.sample(string.ascii_letters + string.digits, 32))
        await self.send_data(writer, self.chap_salt, salt)
        try:
            recv = await asyncio.wait_for(self.recv_data(reader), 5.0)
            if not recv:
                return None
            if recv[0] == 'chap-name':
                name = recv[1]
            else:
                return False
            pwd = self.users.get(name)
            if pwd is None:
                return False
            md5 = hashlib.md5()
            md5.update(salt.encode('utf-8'))
            md5.update(pwd.encode('utf-8'))
            recv = await asyncio.wait_for(self.recv_data(reader), 5.0)
            if not recv:
                return None
            if recv[0] == 'chap-hash':
                hash = recv[1]
            else:
                return False
        except asyncio.TimeoutError:
            return False
        if md5.hexdigest() == hash:
            await self.send_data(writer, self.chap_result, 1)
            return True
        else:
            return False

    def listen(self):
        """ Start server listening the transmit port for slave machine.

            Use asyncio for multi-slave. Run the server only when user
            press Ctrl+C.
        """
        # Start server to listen to the transmit port for slave
        try:
            task = asyncio.start_server(self.proxy_slave_handler, 'localhost', self.transmit_port, loop=self.loop)
            slave_server = self.loop.run_until_complete(task)
            # Serve requests until Ctrl+C is pressed
            try:
                self.loop.run_forever()
            except KeyboardInterrupt:
                for writer in self.connect_ports.values():
                    writer.close()
                for item in self.client_writers.values():
                    for writer in item.values():
                        writer.close()
                slave_server.close()
                self.loop.run_until_complete(slave_server.wait_closed())
        except Exception:
            print('Error while attempting to bind on address (\'127.0.0.1\', %d)\n' % self.transmit_port)
        finally:
            self.loop.close()

    async def proxy_slave_handler(self, slave_reader, slave_writer):
        """ Runs for slave socket connection

            Receive the data from slave and judge and send to the corresponding client.
            The all StreamWriter references are in the dict client_writer.

            Args:
                slave_reader: a StreamReader object
                slave_writer: a StreamWriter object
        """
        addr = slave_writer.get_extra_info('peername')
        print('[slave] Connection request from %s ...' % (addr, ))

        # CHAP challenge
        try:
            res = await self.chap_server(slave_reader, slave_writer)
            if res is None:
                print('The connection with %s is closed!' % (addr, ))
                if not slave_writer.transport.is_closing():
                    slave_writer.close()
                return
            if res is False:
                print('[slave] CHAP Authentication to %s Failed! Closing the connection!' %(addr, ))
                if not slave_writer.transport.is_closing():
                    slave_writer.close()
                return
        except:
            print('[slave] Something Wrong! Please check slave %s' % (addr, ))
            if not slave_writer.transport.is_closing():
                slave_writer.close()
            return
        print('[slave] CHAP Authentication to %s Success!' % (addr, ))

        tasks = []
        t0 = time.clock()
        while True:
            try:
                recv = await self.recv_data(slave_reader)
                if not recv:
                    break
                if recv[0] == 'bind-request':
                    request_id = recv[1]
                    port = recv[2]
                    if port == 0:
                        for i in range(1, 5):
                            port = random.randint(5000, 65535)
                            if self.ports.get(port) == 1:
                                continue
                            try:
                                task = asyncio.start_server(self.proxy_client_handler, 'localhost', port, loop=self.loop)
                                asyncio.ensure_future(task)
                                tasks.append(task)
                                await self.send_data(slave_writer, self.bind_response, (request_id, 1, port))
                                break
                            except:
                                port = 0
                        if port == 0:
                            await self.send_data(slave_writer, self.bind_response, (request_id, 0, port))
                            print('Error while attempting to bind on address (\'127.0.0.1\', %d)\n' % port)
                        else:
                            self.connect_ports[port] = slave_writer
                            self.ports[port] = 1
                            print('Binding address on %d success!' % port)
                    else:
                        try:
                            if self.ports.get(port) == 1:
                                await self.send_data(slave_writer, self.bind_response, (request_id, 0, port))
                                print('Error while attempting to bind on address (\'127.0.0.1\', %d)\n' % port)
                            else:
                                task = asyncio.start_server(self.proxy_client_handler, 'localhost', port, loop=self.loop)
                                asyncio.ensure_future(task)
                                tasks.append(task)
                                await self.send_data(slave_writer, self.bind_response, (request_id, 1 ,port))
                                self.connect_ports[port] = slave_writer
                                self.ports[port] = 1
                                print('Binding address on %d success!' % port)
                        except:
                            await self.send_data(slave_writer, self.bind_response, (request_id, 0, port))
                            print('Error while attempting to bind on address (\'127.0.0.1\', %d)\n' % port)

                elif recv[0] == 'connect-response':
                    request_id = recv[1]
                    result = recv[2]
                    connection_id = recv[3]
                    if result == 1:
                        self.request[request_id] = connection_id
                    else:
                        self.request[request_id] = -1

                elif recv[0] == 'data':
                    connection_id = recv[1]
                    data = recv[2]
                    writer = self.client_writers[slave_writer][connection_id]
                    i = 0
                    while not writer:
                        i = i + 1
                        await asyncio.sleep(0.01)
                        writer = self.client_writers[slave_writer][connection_id]
                        if i == 100:
                            break
                    if writer and not writer.transport.is_closing():
                        writer.write(data)
                    else:
                        break

                elif recv[0] == 'disconnect':
                    connection_id = recv[1]
                    writer = self.client_writers[slave_writer][connection_id]
                    if writer and not writer.transport.is_closing():
                        print('[client] Connection from %s' %(writer.get_extra_info('peername'),))
                        writer.close()

                elif recv[0] == 'heartbeat':
                    t1 = time.clock()
                    if t1-t0 > 20:
                        print('[slave] HeartBeat wrong!')
                        break
                    t0 = t1
                    await self.send_data(slave_writer, self.heartbeat, None)
            except:
                break

        print('[slave] Connection with %s closed!\n' % (addr, ))
        if not slave_writer.transport.is_closing():
            slave_writer.close()
        try:
            for item in self.client_writers.get(slave_writer):
                if item.value().transport is not None and not item.value().transport.is_closing():
                    item.value().close()
        except:
            pass
        # Close the listening server
        for task in tasks:
            task.close()

    async def test_connect(self, request_id):
        """Test whether receive the connection_id or not. 5s Timeout."""
        for i in range(1, 500):
            await asyncio.sleep(0.01)
            if self.request.get(request_id) is not None:
                if self.request.get(request_id) >= 0:
                    return True
                else:
                    return False

    async def proxy_client_handler(self, client_reader, client_writer):
        """ Runs for each client connection

            Receive the data from clients and transmit it to the slave machine.
            The StreamWriter of the slave is SLAVE.

            Args:
                client_reader: a StreamReader object
                client_writer: a StreamWriter object
        """
        client_addr = client_writer.get_extra_info('peername')
        proxy_addr = client_writer.get_extra_info('sockname')
        slave_writer = self.connect_ports.get(proxy_addr[1])

        if not slave_writer:
            print('[client] slave to proxy is already closed!')
            if not client_writer.transport.is_closing():
                client_writer.close()
            return
        print('[client] Connection request from client %s!' % (client_addr, ))
        self.cur_request = (self.cur_request + 1) % 65536
        request_id = self.cur_request
        # A new connect from slave to local server
        try:
            await self.send_data(slave_writer, self.connect_request, (request_id, proxy_addr[1]))
        except:
            print('[client] slave to proxy is already closed!')
            if not client_writer.transport.is_closing():
                client_writer.close()
            return
        try:
            res = await asyncio.wait_for(self.test_connect(request_id), 5.0)
        except asyncio.TimeoutError:
            print('[client] Connection request %s failed!' % (client_addr, ))
            if not client_writer.transport.is_closing():
                client_writer.close()
            return
        if res == True:
            connection_id = self.request.get(request_id)
            self.client_writers[slave_writer][connection_id] = client_writer
            print('[client] Connection from %s received!' % (client_addr, ))
        else:
            print('[client] Connection request %s failed!' % (client_addr, ))
            if not client_writer.transport.is_closing():
                client_writer.close()
            return
        # Data Stream
        while True:
            try:
                data = await client_reader.read(self.buf_size)
                if not data:
                    break
                await self.send_data(slave_writer, self.data, (connection_id, data))
            except Exception:
                break

        # Close the corresponding connection
        print('[client] The connection from %s is closed!\n' % (client_addr, ))
        try:
            await self.send_data(slave_writer, self.disconnect, connection_id)
        except:
            pass
        if not client_writer.transport.is_closing():
            client_writer.close()


class SlaveMachine(Lcx):
    """ Slave Machine in the local.

        Connect to the proxy server, and do the CHAP Authentication from
        the porxy server. After CHAP success, send the bind-request to
        open the listen server of the proxy. Then, receive the connection-
        request from proxy and connect to corresponding local server.

        Attributes:
            remote_addr: the address of the proxy server.
            user: username and password
            ports: bind-request ports
            local_addr: local server address
            proxy_writer: StreamWriter of proxy
            proxy_reader: StreamReader of proxy
            local_writers: StreamWriter of local servers
    """

    def __init__(self, remote_addr, user, ports, local_addr):
        """Init."""
        self.remote_addr = remote_addr
        self.user = user
        self.ports = ports
        self.local_addr = local_addr
        self.proxy_writer = None
        self.proxy_reader = None
        self.local_writers = {}


    async def chap_challenger(self, reader, writer):
        """CHAP receiver."""
        recv = await self.recv_data(reader)
        if not recv:
            return None
        if recv[0] == 'chap-salt':
            salt = recv[1]
        await self.send_data(writer, self.chap_name, self.user[0])
        md5 = hashlib.md5()
        md5.update(salt.encode('utf-8'))
        md5.update(self.user[1].encode('utf-8'))
        await self.send_data(writer, self.chap_hash, md5.hexdigest())
        try:
            recv = await asyncio.wait_for(self.recv_data(reader), 5.0)
            if not recv:
                return None
            if recv[0] == 'chap-result' and recv[1] == 1:
                return True
            else:
                return False
        except asyncio.TimeoutError:
            return False

    async def heartbeat(self):
        while True:
            await asyncio.sleep(10)
            if self.proxy_writer.transport.is_closing():
                break
            try:
                await self.send_data(self.proxy_writer, self.heartbeat, None)
            except:
                break

    def slave(self):
        """ The slave machine exchange data on two sockets.

            Establish one connection to the connect socket for the proxy and another
            transmit socket from inner net. When the two connection established,
            exchange the data on the two sockets.
            The max number of the connections for the inner net is 5 because of
            the limit of the clients.

            Args:
                remote_addr: the ip address and port to the proxy server
                user: the username and password to authenticate
                port: the listen port for local slave to connect
                local_addr: the ip address and port of the inner net machine
        """
        # Connect to proxy server
        task = asyncio.ensure_future(self.slave_proxy_handler())
        # Close all the connections
        try:
            self.loop.run_until_complete(task)
        except KeyboardInterrupt:
            if self.proxy_writer is not None and not self.proxy_writer.transport.is_closing():
                self.proxy_writer.close()
            for writer in self.local_writers.values():
                writer.close()

    async def slave_proxy_handler(self):
        """ Runs for slave to proxy connection

            Receive the data from proxy server and transmit it to the inner net.
            The all StreamWriter references are in the dict INNER_LIST. Each item in
            INNER_LIST correspond to one client.

            Args:
                remote_addr: the ip address and port to the proxy server
                user: the username and password to authenticate
                port: the listen port for local slave to connect
                local_addr: the ip address and port of the inner net machine
                loop: event loop
        """
        # Connecting to proxy server
        for i in range(1, 10):
            try:
                self.proxy_reader, self.proxy_writer = await asyncio.open_connection(self.remote_addr[0], self.remote_addr[1], loop=self.loop)
                print('[proxy] Connecting to proxy server...!')
                i = 0
                break
            except Exception:
                print('Try to connect to %s...' % (self.remote_addr, ))
                await asyncio.sleep(2)
        if i > 0:
            print('[proxy] Error while connection to proxy server!')
            return

        # CHAP Authentication
        try:
            res = await self.chap_challenger(self.proxy_reader, self.proxy_writer)
            if res:
                print('[proxy] Connection to %s success!' % (self.remote_addr, ))
            else:
                print('[proxy] CHAP Authentication failed!')
                if not self.proxy_writer.transport.is_closing():
                    self.proxy_writer.close()
                return
        except:
            print('[proxy] Connection to proxy server closed!')
            if not self.proxy_writer.transport.is_closing():
                self.proxy_writer.close()
            return

        # Send the listen port for proxy server
        request_id = 0
        for port in self.ports:
            request_id = request_id + 1
            try:
                await self.send_data(self.proxy_writer, self.bind_request, (request_id, port))
                try:
                    recv = await asyncio.wait_for(self.recv_data(self.proxy_reader), 7.0)
                    if not recv:
                        print('[proxy] Connection to %s is closed!' % (self.remote_addr))
                        if not self.proxy_writer.transport.is_closing():
                            self.proxy_writer.close()
                        return
                    if recv[0] == 'bind-response' and recv[2] == 1:
                        print('[proxy] Bind port %d success!' % recv[3])
                    else:
                        print('[proxy] Bind port %d failed!' % recv[3])
                except asyncio.TimeoutError:
                    print('[proxy] Bind port request %d failed!' % request_id)
            except Exception:
                print('[proxy] Connection to proxy server closed!')
                if not self.proxy_writer.transport.is_closing():
                    self.proxy_writer.close()
                return

        # Heartbeat
        asyncio.ensure_future(self.heartbeat())

        # Data Stream
        connection_id = -1
        t0 = time.clock()
        while True:
            try:
                recv = await self.recv_data(self.proxy_reader)
                if not recv:
                    break
                if recv[0] == 'connect-request':
                    request_id = recv[1]
                    try:
                        local_reader, local_writer = await asyncio.open_connection(self.local_addr[0], self.local_addr[1], loop=self.loop)
                        print('[local] Connecting to %s success!' % (self.local_addr, ))
                        connection_id = (connection_id + 1) % 65536
                        self.local_writers[connection_id] = local_writer
                        asyncio.ensure_future(self.slave_local_handler(self.local_addr, local_reader, local_writer, connection_id))
                        await self.send_data(self.proxy_writer, self.connect_response, (request_id, 1, connection_id))
                    except Exception:
                        print('Error while connecting to %s\n' %(self.local_addr, ))
                        await self.send_data(self.proxy_writer, self.connect_response, (request_id, 0, 1))

                elif recv[0] == 'data':
                    connection_id = recv[1]
                    data = recv[2]
                    writer = self.local_writers.get(connection_id)
                    if writer and not writer.transport.is_closing():
                        writer.write(data)

                elif recv[0] == 'disconnect':
                    connection_id = recv[1]
                    writer = self.local_writers.get(connection_id)
                    if writer and not writer.transport.is_closing():
                        print('[client] Connection from %s' %(writer.get_extra_info('peername'), ))
                        writer.close()

                elif recv[0] == 'heartbeat':
                    t1 = time.clock()
                    if t1-t0 > 20:
                        print('[proxy] Heartbeat Wrong!')
                        break
                    else:
                        t0 = t1
            except:
                break

        print('[proxy] The connection to remote %s is closed!\n' % (self.remote_addr, ))
        if not self.proxy_writer.transport.is_closing():
            self.proxy_writer.close()
        for writer in self.local_writers.values():
            if not writer.transport.is_closing():
                writer.close()

    async def slave_local_handler(self, local_addr, reader, writer, connection_id):
        """ Runs for slave to local server connection

            Receive the data from inner-net and transmit it to the proxy server.
            The StreamWriter of the proxy is PROXY_WRITER.
            Because the returns of the application may lack the information of the address
            of the client host, so NEED to establish multi-connection between the slave and the
            inner-net, thus ensuring the returning data will be correct.

            Args:
                local_addr: the local server address
                loop: the event loop
                sock: The ip and port of corresponding remote client ip
        """
        # Data Stream
        while True:
            try:
                data = await reader.read(self.buf_size)
                if not data:
                    break
                await self.send_data(self.proxy_writer, self.data, (connection_id, data))
            except Exception:
                break

        # Close the corresponding connection
        print('[local] The connection to %s is closed!\n' % (local_addr, ))
        try:
            await self.send_data(self.proxy_writer, self.disconnect, connection_id)
        except:
            pass
        if not writer.transport.is_closing():
            writer.close()


if __name__ == '__main__':
    argv_process()
