import socket
import time
import io


class DNSRequest:
    def __init__(self, ttl, type, domain):
        self.ttl = ttl
        self.type = type
        self.domain = domain


class DNSData:
    def __init__(self, data):
        self.raw_data = data
        self.raw_data_io = io.BytesIO(data)
        self.query = None
        self.answers = None
        self.header = None
        self.types = self.get_types()
        self.parse_data()

    def parse_data(self):
        self.header = self.raw_data[:12]
        name = self.get_name(self.raw_data[12:],self.raw_data)
        pointer = len(name) + 12
        self.raw_data_io.seek(pointer)
        self.query = self.parse_query()
        self.answers = self.raw_data_io.read()


    def parse_query(self):
        name = self.get_name(self.raw_data[12:], self.raw_data)
        pointer = len(name) + 12
        self.raw_data_io.seek(pointer)
        query = name + self.raw_data_io.read(4)
        return query

    def get_types(self):
        return {b'\x00\x01': 'A',
                b'\x00\x1c': 'AAAA',
                b'\x00\x0f': 'MX',
                b'\x00\x05': 'CNAME',
                b'\x00\x06': 'SOA',
                b'\x00\x02': 'NS',
                b'\x00\x0c': 'PTR',
                b'\x00\x10': 'TXT'}

    def parse_answers(self):
        answers = []
        ans = b''
        answers_start = len(self.header) + len(self.query)
        answrs = self.raw_data[answers_start:]
        answrs_io = io.BytesIO(answrs)

        while len(answrs) != 0:
            name = self.get_name(answrs, self.raw_data)
            length = len(name)
            answrs_io.seek(length)
            entry_type = answrs_io.read(2)
            type_ = self.types[entry_type]
            class_ = answrs_io.read(2)
            ttl = answrs_io.read(4)
            data_len = answrs_io.read(2)
            rdata = io.BytesIO(answrs_io.read(int.from_bytes(data_len, byteorder='big')))
            # if type_ == 'A' or type_ == 'CNAME':
            #     data = rdata.read(data_len)
            #     ans = name + type + class_ + ttl + data_len + data
            # if type_ == 'AAAA':
            #     ans = name + type + class_ + ttl
            # if type_ == 'NS':
            #     n = self.get_name(answrs, self.raw_data)
            #     ans = name + type + class_ + ttl + n
            # if type_ == 'SOA':
            #     serial = answrs_io.read(4)
            #     refresh = answrs_io.read(4)
            #     retry = answrs_io.read(4)
            #     expire = answrs_io.read(4)
            #     ttl = answrs_io.read(4)
            #     ans = name + type + class_ +ttl + serial + refresh + retry + expire + ttl
            # if type_ == 'TXT':
            #     data_len = answrs_io.read(2)
            #     txt_data = answrs_io.read(int(data_len, 16))
            #     ans = name + type + class_ + ttl + data_len + txt_data
            # else:
            #     continue
            ans = self.form_answers(type_, rdata, data_len, answrs)
            temp = name + entry_type + class_ + ttl + data_len + ans
            answers.append(temp)
            answrs = answrs[len(temp):]

        return answers
        #todo: нужно ли парсить данные?

    def form_answers(self, type_, rdata, data_len, answrs):
        ans = None
        if type_ == 'A' or type_ == 'CNAME':
            data = rdata.read(data_len)
            ans = data
        # if type_ == 'AAAA':
        #     ans = name + type_ + class_ + ttl
        if type_ == 'NS':
            n = self.get_name(answrs, self.raw_data)
            ans = n
        if type_ == 'SOA':
            serial = rdata.read(4)
            refresh = rdata.read(4)
            retry = rdata.read(4)
            expire = rdata.read(4)
            ttl = rdata.read(4)
            ans = serial + refresh + retry + expire + ttl
        if type_ == 'TXT':
            txt_data = rdata.read(int(data_len, 16))
            ans = txt_data
        else:
            return
        return ans

    @staticmethod
    def add_padding(number, length): #number-str
        dif = length - len(number)
        new_num = '0'*dif + number
        return new_num

    def get_name(self, proper_data, full_data):
        name = b''
        data_io = io.BytesIO(proper_data)
        full_data_io = io.BytesIO(full_data)
        while True:
            length = data_io.read(1)
            if length == b'\x00':
                break
            l = bin(int.from_bytes(length, byteorder='big'))[2:]   #биты
            l = DNSData.add_padding(l, 8)
            if l.startswith('11'):
                l2 = data_io.read(1)
                link = bin(int(l[2:], 2) + int.from_bytes(l2, byteorder='big')) #двоичное число
                link = int(link, 2) #десятичное число
                full_data_io.seek(link)
                data_io = full_data_io #todo: возможно не так
                continue
            else:
                name += length
                name += data_io.read(int.from_bytes(length, byteorder='big'))
        return name


class DNSServer():
    def __init__(self, addr, port, server):
        self.addr = addr
        self.port = port
        self.server = server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cache = Cache()

    def start(self):
        print('started')
        self.socket.bind(('localhost', self.port))
        while True:
            print('loop')
            data, addr = self.socket.recvfrom(512) #максимально возможное количество полученных байт в UDP
            # self.in_cache()#свериться с кэшем
            # resp = self.send_to_server(data)
            print('Got it')
            response = DNSData(data)
            name = response.get_name(data[12:], full_data=data)
            print(name)
            self.in_cache(name, data)  # свериться с кэшем
            resp = self.send_to_server(data) # todo: или что тут должно быть в кеше
            self.socket.sendto(resp, addr)

    def in_cache(self, name, data):
        if not self.cache[name]:
            self.cache.add_element((name, data))


    def send_to_server(self, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self.server, 53))
        sock.send(data)
        responce = sock.recv(512)
        return responce


class Cache:
    def __init__(self):
        self.cache = []

    def __getitem__(self, item):
        for i in range(len(self.cache)):
            if self.cache[i][0] == item:
                return self.cache[i][1]
        return  None

    def __setitem__(self, key, value):
        if not self.cache.__getitem__(key):
            self.cache.append((key, value))

    def add_element(self, element):
        self.cache.append(element)


serv = DNSServer('localhost', 53, '8.8.8.8')
serv.start()