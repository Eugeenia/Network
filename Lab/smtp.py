import socket
import ssl
import base64
import os.path


CONFIG_FILE = 'config.txt'
TEXT_FILE = 'text.txt'


def make_request():
    login = input('Input your login:')
    password = input('Input your password:')
    name = input('Input your name')
    directory = input('Input directory') #где лежат все файлы
    recievers, subject, attachments, text = parse_files(directory)
    request = ['EHLO ' + login[:login.find('@')],
               'AUTH LOGIN',
               base64.b64encode(login.encode()).decode(),
               base64.b64encode(password.encode()).decode(),
               'MAIL FROM: ' + login,
               *['RCPT TO: ' + recv for recv in recievers],
               'DATA',
               make_letter(login, name, recievers, subject, text, attachments, directory),
               'QUIT']
    return request


def make_letter(login, name, recievers, subject, text, attachments, directory):
    l = base64.b64encode(login.encode()).decode()
    letter = ''
    letter += 'From: {}<{}>\n'.format(login, name)
    for recv in recievers:
        letter += 'To: {}\n'.format(recv)
    letter += 'Subject: =?UTF-8?B?{}?=\n'.format(base64.b64encode(subject.encode()).decode())
    boundary = 'boundaryText'
    if attachments:
        letter += 'Content-Type: multipart/mixed; boundary={};\n\n'.format(boundary)
        if text:
            letter += '--{}\n'.format(boundary)
            letter += 'Content-Type: text/plain; charset=utf-8\n'
            letter += 'Content-Transfer-Encoding: base64\n\n'
            letter += base64.b64encode(text.encode()).decode() + '\n.'
        for attachment in attachments:
            print(attachment)
            kind = attachment.split('.')
            print(kind)
            k = kind[-1]
            print(k)
            cont_type = get_type(k)
            letter += '--{}\n'.format(boundary)
            letter += 'Content-Type: {}\nContent-Transfer-Encoding:base64\n'.format(cont_type)
            letter += 'Content-Disposition:attachment; filename="{}"\n\n'.format(attachment)
            letter += '{}\n\n'.format(encode_attachment_to_base64(directory, attachment))
        letter += '--{}--\n'.format(boundary)
    else:
        letter += 'Content-Type: text/plain; charset=utf-8\n'
        letter += 'Content-Transfer-Encoding: base64\n\n'
        letter += base64.b64encode(text.encode()).decode()
    print(letter + '\n.')
    return letter + '\n.'


def encode_attachment_to_base64(directory, atttachment):
    file = directory + atttachment
    with open(file, 'rb') as a:
        return base64.b64encode(a.read()).decode()


def parse_files(directory):
    config_file = os.path.join(directory, CONFIG_FILE)
    text_file = os.path.join(directory, TEXT_FILE)
    with open(config_file, 'r') as conf:
        recievers = conf.readline()[4:]
        recievers = recievers.split()
        print(recievers)
        subject = conf.readline()[9:]
        attachments = conf.readline()[13:]
        print(attachments)
        attachments = attachments.split()
        print(attachments)
    with open(text_file, 'r') as text_file:
        text = text_file.read()
    return recievers, subject, attachments, text


def smtp(addr, port, to_send):
    ssl_socket = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, port))
    ssl_socket = ssl.wrap_socket(sock)
    data = ssl_socket.recv(1024)
    print(data.decode())
    for i in to_send:
        message = i + '\r\n'
        ssl_socket.send(message.encode())
        answer = ssl_socket.recv(1024)
        print(answer.decode())
    ssl_socket.close()


def get_type(kind):
    types = {'jpg': 'image/jpeg',
             'jpeg': 'image/jpeg',
             'png': 'image/png',
             'gif': 'image/gif',
             'doc': 'application/msword',}
    return types[kind]


to_send = make_request()
smtp('smtp.yandex.ru', 465, to_send)
