from z3 import *

"""
First, use a debugger (fceux on windows) to find the section of code that verifies the key.
The way I found this was looking for the function that accesses the $4016 register to read input and then found
all places that jumped (jsr) to it.

Next, there was a spot of code that checked for a bunch of different buttons, so it was likely
the part where you set the password.

After stepping through the code, the program uses the return value of this routine to determine whether
you passed the challenge.

 00:82F1:A0 00     LDY #$00
 00:82F3:A9 00     LDA #$00
 00:82F5:85 3B     STA $003B
 00:82F7:B9 05 00  LDA $0005,Y @ $000D ;; load next char
 00:82FA:AA        TAX                 ;; a -> x
 00:82FB:2A        ROL                 ;; rot a left
 00:82FC:8A        TXA                 ;; x -> a
 00:82FD:2A        ROL                 ;; rot a left +
 00:82FE:AA        TAX                 ;; a -> x
 00:82FF:2A        ROL                 ;; rot a left
 00:8300:8A        TXA                 ;; x -> a
 00:8301:2A        ROL                 ;; rot a left +
 00:8302:AA        TAX                 ;; a -> x
 00:8303:2A        ROL                 ;; rot a left 
 00:8304:8A        TXA                 ;; x -> a
 00:8305:2A        ROL                 ;; rot a left +
 00:8306:48        PHA                 ;; push a
 00:8307:A5 3B     LDA $003B           ;; <-- load from 831A
 00:8309:AA        TAX                 ;; a -> x
 00:830A:6A        ROR                 ;; rot a right
 00:830B:8A        TXA                 ;; x -> a
 00:830C:6A        ROR                 ;; rot a right
 00:830D:AA        TAX                 ;; a -> x
 00:830E:6A        ROR                 ;; rot a right
 00:830F:8A        TXA                 ;; x -> a
 00:8310:6A        ROR                 ;; rot a right
 00:8311:85 3B     STA $003B = #$0D    ;; store into tmp
 00:8313:68        PLA                 ;; pull out a
 00:8314:18        CLC                 ;; clear carry
 00:8315:65 3B     ADC $003B = #$0D    ;; add val at 3b
 00:8317:59 5E 95  EOR $955E,Y @ $9566 ;; xor with first key
 00:831A:85 3B     STA $003B = #$0D    ;; store at 3b
 00:831C:AA        TAX                 ;; flip the first 4 bits 
 00:831D:2A        ROL-                ;; with the last 4 bits
 00:831E:8A        TXA
 00:831F:2A        ROL+
 00:8320:AA        TAX
 00:8321:2A        ROL-
 00:8322:8A        TXA
 00:8323:2A        ROL+
 00:8324:AA        TAX
 00:8325:2A        ROL-
 00:8326:8A        TXA
 00:8327:2A        ROL+
 00:8328:AA        TAX
 00:8329:2A        ROL-
 00:832A:8A        TXA
 00:832B:2A        ROL+
>00:832C:59 76 95  EOR $9576,Y @ $957E ;; xor with 2nd key
 00:832F:99 1E 00  STA $001E,Y @ $0026 ;; store result
 00:8332:C8        INY
 00:8333:C0 18     CPY #$18
 00:8335:D0 C0     BNE $82F7
 00:8337:A0 00     LDY #$00
 00:8339:B9 1E 00  LDA $001E,Y @ $0026 = #$88
 00:833C:D0 08     BNE $8346
 00:833E:C8        INY
 00:833F:C0 18     CPY #$18
 00:8341:D0 F6     BNE $8339
 00:8343:A9 01     LDA #$01
 00:8345:60        RTS -----------------------------------------
 00:8346:A9 00     LDA #$00
 00:8348:60        RTS -----------------------------------------

The algorithm is pretty straightforward, but there are two keys that
it uses to verify the key. The goal is to have the results stored at
$0026 all be zero, so that it returns 1 instead of zero.

Using a debugger, you can extract the two keys. You could probably compute
the password directly, but I think it was much easier to use an SMT solver.
The assembly isn't too bad, every two rotations accomplish one rotation thanks
to how the 6502 rotates.

    TAX ;; put A into X
    ROL ;; rotate left (possibly shifting the msb into the Carry flag)
    TXA ;; restore A
    ROL ;; rotate left (the carry, if set, will now go to the lsb, like we would expect.

With this simplification, you can just describe the algorithm to Z3 and the requirements
(that all x's be ascii characters in a certain range), and it will generate the password
for you.

What's really cool is that it takes 187ms to generate the password.
"""

xs = BitVecs('x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x22 x23', 8)
ts = BitVecs('t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 t15 t16 t17 t18 t19 t20 t21 t22', 8)
s = Solver()

secret0 = [0x70,0x30,0x53,0xA1,0xD3,0x70,0x3F,0x64,0xB3,0x16,0xE4,0x04,0x5F,
           0x3A,0xEE,0x42,0xB1,0xA1,0x37,0x15,0x6E,0x88,0x2A,0xAB]

secret1 = [0x20,0xAC,0x7A,0x25,0xD7,0x9C,0xC2,0x1D,0x58,0xD0,0x13,0x25,0x96,
           0x6A,0xDC,0x7E,0x2E,0xB4,0xB4,0x10,0xCB,0x1D,0xC2,0x66]

# Restrict each byte to an alphanumeric character 
for x in xs:
    s.add(Or(x == 0x20, And(x >= 0x31, x <= 0x39), And(x >= 0x41, x <= 0x5a)))

for i in range(24):
    s0 = secret0[i]
    s1 = secret1[i]
    
    x = xs[i]
    
    a = RotateLeft(x, 3)

    if (i == 0):
        temp = BitVecVal(0, 8)
    else:
        temp = ts[i-1]

    intermediate = (a + RotateRight(temp, 2)) ^ s0

    if (i < 23):
        ntemp = ts[i]
        s.add(ntemp == intermediate)
    
    s.add((RotateLeft(intermediate, 4) ^ s1) == 0x0)
    
print s.check()
model = s.model()

password = ""

for x in xs:
    password += chr(model[x].as_long())
    
print password
