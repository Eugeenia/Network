import socket
import sys
import re
import subprocess

class Tracert():
    def __init__(self):
        pass

    def trace(self, ip):
        ip = socket.gethostbyname(ip)
        info = subprocess.check_output(['tracert', ip]).decode(errors='ignore')
        index = info.find('*')
        if index != -1:
            info = info[:index]
        return info

    def parse(self, ip):
        info = self.trace(ip).split('\r').__str__()
        info = info.split('\n')
        number = 0
        with open('out.txt', 'a') as f:
            f.truncate(0)
            for line in info:
                ip_ad = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
                for ip_address in ip_ad:
                    ip_address = ip_address.__str__() if ip else None
                    if ip_address is not None:
                        number += 1
                        a_s = self.get_as(ip_address, 'whois.ripe.net')
                        a_system = a_s
                        str_to_write = '{} {} {}{}'.format(number, ip_address, a_system, '\n')
                        f.write(str_to_write)
        with open('out.txt', 'r') as f:
            for line in f:
                print('Final line: {}'.format(line))
        return f

    def get_as(self, ip_addr, whois):
        to_watch = ['whois.ripe.net',
                    'whois.arin.net',
                    'whois.apnic.net',
                    'whois.lacnic.net',
                    'whois.afrinic.net']
        origin = ''
        info = self.get_info(ip_addr, whois)
        print(info)
        orig = re.search(r'(?<=AS)[0-9]+', info)
        print('Orig: {}'.format(orig))
        if orig:
            origin = 'AS{}'.format(orig.group(0))
        elif orig == None:
            origin = 'Black ip'
        else:
            whois_to_watch = to_watch.__iter__().__next__()
            self.get_as(ip_addr, whois_to_watch)
        return origin

    @staticmethod
    def get_info(ip_addr, whois):
        data = ''
        sock_request = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_request.connect((whois, 43))
        sock_request.send(('{}{}'.format(ip_addr, '\r\n')).encode())
        while True:
            d = sock_request.recv(4096).decode()
            data += d
            if not d:
                break
        sock_request.close()
        return str(data)


tr = Tracert()
print(tr.parse('195.34.53.54'))
