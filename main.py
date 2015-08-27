from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.Signature import PKCS1_v1_5 as PKCS
from binascii import hexlify, unhexlify
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
import urllib.request
import threading
import datetime
import cgi
import ssl
import re
import os

# Globals

#   Password for command line interface
PASSWORD = SHA512.new(b'default').hexdigest()

#   Password list for web interface
PASSWORDS = [
    SHA512.new(b'default').hexdigest()
]


CIPHERSUITE = 'ECDH-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA256:HIGH:!aNULL:!MD5:!SHA1'
SSLTLSTYPE =                                                              ssl.PROTOCOL_TLSv1_2
LOGFILE =                                                                     'passmanager.log'
REGEX =                    '<font color="black" face="courier new,courier" size=2>(.*?)</font>'
ENTRY =                                                                                      2
CERT =                                                                        'certificate.crt'
PORT =                                                                                     444
URL =                                                           'https://grc.com/passwords.htm'
KEY =                                                                         'certificate.key'
IP =                                                                                         ''
N =                                                                                       4096

LOGFILE = 'passmanager.log'

try:
    with open('index.html', 'r') as handle:
        INDEX = bytes(handle.read(), 'UTF-8')
    handle.close()
except:
    INDEX = "<!-- Error ->"


class PasswordManager(object):
    @staticmethod
    def logger(message):
        message = '[%s] %s\n' % (datetime.datetime.now().strftime('%a %d %Y - %H:%M:%S'), message)

        with open(LOGFILE, 'a') as handle:
            handle.write(message)
        handle.close()

    def get_pass(self, key, cmnd=False):
        if not cmnd:
            self.logger('[WEB] Password retrieval requested. Importing keys and creating hashes.')

        private_key_hash = SHA512.new(key).hexdigest()
        private_rsa_key = RSA.importKey(key.decode('UTF-8'))

        if not cmnd:
            self.logger('Searching table for entry: \'%s\'.' % private_key_hash)

        l = ''
        for line in open('table', 'r'):
            if line.split(':')[0] == private_key_hash:
                l = line.split(':')
                break
        else:
            raise Exception('Key provided matches no entries in the table.')        

        public_rsa_key = unhexlify(l[1])
        encrypted_pass = unhexlify(l[2])
        metadata = unhexlify(l[3])
        signature = unhexlify(l[4].rstrip('\n'))

        sha_instance = SHA512.new(bytes(private_key_hash, 'UTF-8'))
        sha_instance.update(bytes(SHA512.new(public_rsa_key).hexdigest(), 'UTF-8'))
        sha_instance.update(encrypted_pass)
        sha_instance.update(metadata)

        public_rsa_key = RSA.importKey(public_rsa_key)
        if not PKCS.new(public_rsa_key).verify(sha_instance, signature):
            if not cmnd:
                self.logger('Signature may be corrupt')

            raise Exception(
                'Key provided matched entry, however verification of the signature failed, indicating corruption of the key or signature. Key cannot be returned to a plaintext state.')

        self.logger('Success.')
        return private_rsa_key.decrypt(encrypted_pass).decode('UTF-8'), metadata.decode('UTF-8').split('-')

    def new_pass(self, metadata, genpass=True, password='', cmnd=False):
        if not cmnd:
            self.logger('[WEB] New password requested. Generating new keypair.')

        private_rsa_key = RSA.generate(N)
        public_rsa_key = private_rsa_key.publickey()

        if genpass:
            data = urllib.request.urlopen(URL).read()
            passwords = re.findall(bytes(REGEX, 'UTF-8'), data)

            password = passwords[ENTRY]
        
        try:
            encrypted_pass = list(public_rsa_key.encrypt(bytes(password, 'UTF-8'), 0))[0]
        except:
            encrypted_pass = list(public_rsa_key.encrypt(password, 0))[0]

        del password

        private_key_hash = SHA512.new(private_rsa_key.exportKey()).hexdigest()
        public_key_hash = SHA512.new(public_rsa_key.exportKey()).hexdigest()

        sha_instance = SHA512.new(bytes(private_key_hash, 'UTF-8'))
        sha_instance.update(bytes(public_key_hash, 'UTF-8'))
        sha_instance.update(encrypted_pass)
        sha_instance.update(bytes('-'.join(metadata), 'UTF-8'))

        signature = PKCS.new(private_rsa_key).sign(sha_instance)
        del sha_instance

        with open('table', 'a+') as handle:
            handle.write('%s:%s:%s:%s:%s\n' % (
            str(private_key_hash), hexlify(public_rsa_key.exportKey()).decode('UTF-8'), hexlify(encrypted_pass).decode('UTF-8'),
            hexlify(bytes('-'.join(metadata), 'UTF-8')).decode('UTF-8'), hexlify(signature).decode('UTF-8')))
        handle.close()

        pm.logger('Success - Password inserted. Signature: \'%s\'' % private_key_hash)
        return private_rsa_key.exportKey()


class HTTPServerInstance(BaseHTTPRequestHandler):
    def version_string(self):
        return ""

    def log_message(self, *p):
        fmt = list(p)[0]
        fmt = fmt % tuple(p[1:])

        logline = '%s - %s' % ('%s:%d' % self.client_address, fmt)

        pm.logger(logline)

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers.get('content-type'))

        if ctype == 'multipart/form-data':
            pdict['boundary'] = bytes(pdict['boundary'], 'UTF-8')

            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.get('content-length'))
            postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}

        if 'private_key' in postvars:

            if 'password' in postvars:
                if not SHA512.new(postvars['password'][0]).hexdigest() in PASSWORDS:
                    self.log_message('%s', 'Incorrect password specified.')
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(INDEX)
                    return
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(INDEX)
                return

            try:
                password, metadata = pm.get_pass(postvars['private_key'][0])
            except Exception as e:
                print(e)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(INDEX)
                return

            self.send_file(metadata[0], password)

        elif b'new_pass' in postvars:
            if b'password' in postvars:
                if not SHA512.new(postvars[b'password'][0]).hexdigest() in PASSWORDS:
                    self.log_message('%s', 'Incorrect password specified.')
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(INDEX)
                    self.wfile.write(bytes('</center></body></html>', 'UTF-8'))
                    return
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(INDEX)
                self.wfile.write(bytes('</center></body></html>', 'UTF-8'))
                return

            if b'output_name' in postvars:
                if postvars[b'output_name'][0] != b'':
                    o_n = postvars[b'output_name'][0].decode('UTF-8')
                else:
                    o_n = 'newkey.key'
            else:
                o_n = 'newkey.key'

            metadata = [o_n, str(N)]
            key = pm.new_pass(metadata)

            self.send_file(o_n, key)

        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(INDEX)

    def send_file(self, filename, data):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Disposition', 'attachment; filename=%s\r\n' % filename)
        self.end_headers()

        try:
            self.wfile.write(bytes(data.lstrip('\n'), 'UTF-8'))
        except:
            self.wfile.write(data)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(INDEX)


class ServerHandler(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        Server = HTTPServer((IP, PORT), HTTPServerInstance)
        
        self.ssl_context = ssl.SSLContext(SSLTLSTYPE)
        self.ssl_context.set_ciphers(CIPHERSUITE)
        self.ssl_context.load_cert_chain(certfile=CERT, keyfile=KEY)

        Server.socket = self.ssl_context.wrap_socket(Server.socket, server_side=True)
        Server.serve_forever()


class Cli(object):
    def __init__(self):
        self.main()

    @staticmethod
    def get_password():
        password = input('This command requires a password\n> ')

        if SHA512.new(password.encode('utf-8')).hexdigest() != PASSWORD:
            return False

        return True

    def main(self):
        while True:
            password = input('Enter password\n> ')
            if SHA512.new(password.encode('utf-8')).hexdigest() != PASSWORD:
                pm.logger('[CLI] Local authentication failure.')
                continue

            print('Logged in to Password Manager Interactive CLI!')
            pm.logger('[CLI] Local authentication success.')

            while True:
                cmd = input('> ')
                print('')

                cmd = cmd.split()

                if len(cmd) == 0:
                    continue

                if cmd[0] == 'generate':
                    if len(cmd) > 1:
                        filename = cmd[1]
                    else:
                        filename = 'temp'

                    print('Generating new password')
                    pm.logger('[CLI] New password generation ordered. Filename: %s.' % cmd[1])
                    key = pm.new_pass([filename], cmnd=True)

                    print('Password generated.')
                    with open(filename, 'w') as handle:
                        handle.write(key.decode('UTF-8'))
                    handle.close()

                elif cmd[0] == 'insert':
                    if len(cmd) < 3:
                        print('Not enough args')
                        continue

                    print('Inserting password with filename \'%s\' in to table.' % cmd[2])
                    pm.logger('[CLI] Password insertion ordered. Filename: %s.' % cmd[2])
                    key = pm.new_pass([cmd[2]], genpass=False, password=cmd[1], cmnd=True)

                    print('Password inserted.')
                    with open(cmd[2], 'w') as handle:
                        handle.write(key)
                    handle.close()

                elif cmd[0] == 'list':
                    print('Listing password metadata in table.')
                    pm.logger('[CLI] Table metadata listing ordered.')

                    i = 1
                    for data in open('table', 'r'):
                        sha, key, enc_pass, metadata, signature = data.split(':')
                        del key, enc_pass, signature

                        print('%d  %s  %s' % (i, unhexlify(bytes(metadata, 'UTF-8')).decode('UTF-8').split('-')[0], sha))
                        i += 1

                elif cmd[0] == 'parse':
                    if len(cmd) < 2:
                        print('Not enough args')
                        continue

                    print('Parsing file: \'%s\'.' % cmd[1])
                    pm.logger('[CLI] Parsing of file \'%s\' requested.' % cmd[1])

                    if not (os.path.exists('Keys') and os.path.isdir('Keys')):
                        os.mkdir('Keys')

                    try:
                        i = 1
                        for line in open(cmd[1], 'r'):
                            print('Parsing line %d' % i)

                            data = line.split()
                            key = pm.new_pass([data[0]], genpass=False, password=data[1], cmnd=True)

                            if os.path.exists('Keys/%s' % data[0]) and (not os.path.isdir('Keys/%s' % data[0])):
                                while True:
                                    print('Warning, file %s already exists in directory Keys. (C)ontinue, (R)ename')

                                    warn_response = input('> ').lower()

                                    if warn_response == 'r':
                                        name = input('Enter new name for %s\n> ' % data[0])
                                        name = name.split()[0].split('/')[0]

                                        data[0] = name
                                        break

                                    elif warn_response == 'c':
                                        pm.logger('Overwriting keyfile \'%s\' with new key.' % data[0])
                                        break

                            with open('Keys/%s' % data[0], 'w') as handle:
                                handle.write(key.decode('UTF-8'))
                            handle.close()
                            i += 1

                    except IOError as e:
                        pm.logger('Error ocurred: e.message')
                        print('Error ocurred:\n%s' % e.message)

                elif cmd[0] == 'remove':
                    if not self.get_password():
                        continue

                    if len(cmd) < 2:
                        print('Not enough args.')
                        continue

                    pm.logger('[CLI] Removal of passwords ordered: %s' % ' '.join(cmd[1:]))
                    lines_for_removal = cmd[1:]

                    for line in lines_for_removal:
                        if line.isdigit():
                            lines_for_removal[lines_for_removal.index(line)] = int(line)
                            continue

                        print('All arguments to this command must be integers.')
                        break
                    else:
                        with open('table', 'r') as handle:
                            lines = handle.readlines()
                        handle.close()

                        for line in lines_for_removal:
                            if line in range(1, len(lines) + 1):
                                continue

                            print('All arguments must be within bounds of the table entries.')
                            break
                        else:

                            temp = 0
                            for line in sorted(lines_for_removal, key=int, reverse=True):
                                del lines[line - 1]

                            with open('table', 'w') as handle:
                                for line in lines:
                                    handle.write(line)

                elif cmd[0] == 'clear':
                    os.system('clear')

                elif cmd[0] == 'logout':
                    pm.logger('[CLI] User logged out of CLI Interface.')
                    os.system('clear')
                    break


if __name__ == '__main__':
    pm = PasswordManager()
    HTTPHandler = ServerHandler()
    HTTPHandler.start()

    Cli()
