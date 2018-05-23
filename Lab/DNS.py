import socket
import datetime
import io
import Cache


class DnsEntry:
    def __init__(self, name, clazz, type_, ttl, length, data):
        self.name = name
        self.clazz = clazz
        self.type_ = type_
        self.ttl = ttl
        self.die = datetime.timedelta(seconds=int.from_bytes(ttl, byteorder='big')) + datetime.datetime.today()
        self.length = length
        self.data = data
        self.appear = datetime.datetime.today()

    def __repr__(self):
        return f'name: {self.name}, class: {self.clazz}, type: {self.type_}, ' \
               f'ttl: {self.ttl}, data: {self.data}'

    def __str__(self):
        return f'name: {self.name}, class: {self.clazz}, type: {self.type_}, ' \
               f'ttl: {self.ttl}, data: {self.data}'


class DnsData:
    def __init__(self, data):
        self.raw_data = data
        self.raw_data_io = io.BytesIO(data)
        self.query = None
        self.answers = None
        self.type = None
        self.ttl = 0
        self.appear = datetime.datetime.today()
        self.id = self.raw_data_io.read(2)
        self.header = None
        self.types = self.get_types()
        self.entries = []
        self.parse_data()
        self.pointers = dict()

    def parse_data(self):
        self.header = self.raw_data[:12]
        name = self.get_name(io.BytesIO(self.raw_data[12:]), self.raw_data)
        pointer = len(name) + 12
        self.raw_data_io.seek(pointer)
        self.parse_query()
        self.answers = self.raw_data_io.read()

    def parse_query(self):
        name = self.get_name(io.BytesIO(self.raw_data[12:]), self.raw_data)
        pointer = len(name) + 12
        self.raw_data_io.seek(pointer)
        self.type = self.raw_data_io.read(2)
        self.query = name + self.type + self.raw_data_io.read(2)
        packet_type = self.raw_data[2:4]
        if packet_type == b'\x01\x20':
            return
        self.parse_answers()

    def parse_answers(self):
        ans = b''
        answers_start = len(self.header) + len(self.query)
        answrs = self.raw_data[answers_start:]
        answrs_io = io.BytesIO(answrs)

        while len(answrs) != 0:
            name = self.get_name(answrs_io, self.raw_data)
            type_ = answrs_io.read(2)
            class_ = answrs_io.read(2)
            self.ttl = answrs_io.read(4)
            data_len = answrs_io.read(2)
            rdata = io.BytesIO(answrs_io.read(int.from_bytes(data_len, byteorder='big')))
            ans = self.form_answers(rdata, data_len)
            temp = name + type_ + class_ + self.ttl + data_len
            if ans is None:
                answrs = answrs[len(temp) + int.from_bytes(data_len, byteorder='big'):]
                continue
            temp += ans
            entry = DnsEntry(name, class_, type_, self.ttl, data_len, ans)
            self.entries.append(entry)
            answrs = answrs[len(temp):]

    def form_answers(self, rdata, data_len):
        if self.type == b'\x00\x01' or self.type == b'\x00\x05':
            data = rdata.read(int.from_bytes(data_len, byteorder='big'))
            ans = data
        elif self.type == b'\x00\x02':
            n = self.get_name(rdata, self.raw_data)
            ans = n
        elif self.type == b'\x00\x06':
            mname = self.get_name(rdata, self.raw_data)
            rname = self.get_name(rdata, self.raw_data)
            serial = rdata.read(4)
            refresh = rdata.read(4)
            retry = rdata.read(4)
            expire = rdata.read(4)
            ttl = rdata.read(4)
            ans = mname + rname + serial + refresh + retry + expire + ttl
        elif self.type == b'\x00\x10':
            txt_data = rdata.read(int(data_len, 16))
            ans = txt_data
        else:
            return
        return ans

    def get_types(self):
        return {b'\x00\x01': 'A',
                b'\x00\x05': 'CNAME',
                b'\x00\x06': 'SOA',
                b'\x00\x02': 'NS',
                b'\x00\x10': 'TXT'}

    @staticmethod
    def add_padding(number, length):  # number-str
        dif = length - len(number)
        new_num = '0' * dif + number
        return new_num

    def get_name(self, proper_data, full_data):
        name = b''
        data_io = proper_data
        full_data_io = io.BytesIO(full_data)
        while True:
            length = data_io.read(1)
            if length == b'\x00':
                break
            l = bin(int.from_bytes(length, byteorder='big'))[2:]   #биты
            l = DnsData.add_padding(l, 8)
            if l.startswith('11'):
                l2 = data_io.read(1)
                link = bin(int(l[2:], 2) + int.from_bytes(l2, byteorder='big')) #двоичное число
                link = int(link, 2) #десятичное число
                full_data_io.seek(link)
                data_io = full_data_io
                continue
            else:
                name += length
                name += data_io.read(int.from_bytes(length, byteorder='big'))
        return name + b'\x00'



class DnsServer:
    def __init__(self, addr, port, server):
        self.addr = addr
        self.port = port
        self.server = server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cache = Cache.Cache()
        self.response = None
        self.standard_response = b'\x81\x80'

    def start(self):
        print('started')
        self.socket.bind(('localhost', self.port))
        while True:
            print('loop')
            data, addr = self.socket.recvfrom(512)
            print('Got it')
            self.response = DnsData(data)
            name = self.response.get_name(io.BytesIO(data[12:]), full_data=data)
            type = self.response.type
            self.cache.validate_cache()
            print(f'In cache: {self.in_cache((type, name))}')
            if self.in_cache((type, name)):
                resp = self.cache[(type, name)]
                answer = self.make_answer(resp, data)
                if answer:
                    self.socket.sendto(answer, addr)
                    print(f'RESPONSE: {answer}')
                    continue
            print('Enter')
            resp = self.send_to_server(data)
            dns_data = DnsData(resp)
            self.update_cache(dns_data)
            print(f'cache: {self.cache}')
            self.socket.sendto(resp, addr)

    def make_answer(self, resp, data):
        answer = b''
        if resp:
            act_len = 0
            answer += data[:2]
            answer += self.standard_response
            answer += data[4:6]
            answer += b'\x00\x00'
            answer += b'\x00\x00'
            answer += b'\x00\x00'
            answer += data[12:len(self.response.query) + 12]
            for entry in resp:
                n = entry.name
                c = entry.clazz
                t = entry.type_
                l = int.to_bytes(len(entry.data), 2, byteorder='big')
                ttl = int.from_bytes(entry.ttl, byteorder='big') - (datetime.datetime.today() - entry.appear).seconds
                if ttl > 0:
                    ttl = int.to_bytes(ttl, 4, byteorder='big')
                    d = entry.data
                    answer += n + t + c + ttl + l + d
                    act_len += 1
            if act_len == 0:
                return
            answer = answer[:6] + int.to_bytes(act_len, 2, byteorder='big') + answer[8:]
            return answer

    def send_to_server(self, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self.server, 53))
        sock.send(data)
        response = sock.recv(512)
        return response

    def update_cache(self, dns_data):
        for answer in dns_data.entries:
            self.cache[(answer.type_, answer.name)] = answer

    def in_cache(self, key):
        return key in self.cache


serv = DnsServer('localhost', 53, '8.8.8.8')
serv.start()
