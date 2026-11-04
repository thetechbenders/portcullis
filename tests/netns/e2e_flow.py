#!/usr/bin/env python3
"""Live, bidirectional UDP oracle. Same sockets before/after loss of authority."""
import pathlib
import select
import socket
import sys
import time

role, prefix, guest_ip = sys.argv[1:]
base = pathlib.Path(prefix)

def mark(s):
    pathlib.Path(prefix + '.' + s).write_text('1')

def exists(s):
    return pathlib.Path(prefix + '.' + s).exists()

def await_mark(s):
    end = time.monotonic() + 75
    while not exists(s):
        if time.monotonic() > end:
            raise TimeoutError(s)
        time.sleep(.02)

wan = ('198.18.0.2', 19122)
guest = (guest_ip, 19123)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(wan if role == 'server' else guest)
    sock.settimeout(5)
    if role == 'server':
        mark('bound')
        sent = False
        end = time.monotonic() + 100
        while not exists('done'):
            if time.monotonic() > end:
                raise TimeoutError('flow server')
            if exists('probing') and not sent:
                sock.sendto(b'BLOCKIN', guest)
                sent = True
                mark('sent')
            if not select.select([sock], [], [], .02)[0]:
                continue
            data, addr = sock.recvfrom(64)
            assert addr == guest, addr
            if data == b'BLOCKOUT':
                mark('leaked')
            elif data in (b'INIT', b'RESTORE'):
                sock.sendto(data, guest)
            else:
                raise AssertionError(data)
    else:
        sock.sendto(b'INIT', wan)
        assert sock.recvfrom(64) == (b'INIT', wan)
        mark('ready')
        await_mark('trigger')
        sock.sendto(b'BLOCKOUT', wan)
        mark('probing')
        await_mark('sent')
        sock.settimeout(3)
        try:
            data = sock.recvfrom(64)
        except socket.timeout:
            pass
        else:
            raise AssertionError(('inbound leak', data))
        assert not exists('leaked'), 'outbound leak'
        mark('blocked')
        await_mark('resume')
        sock.settimeout(5)
        sock.sendto(b'RESTORE', wan)
        assert sock.recvfrom(64) == (b'RESTORE', wan)
        mark('recovered')
        mark('done')
