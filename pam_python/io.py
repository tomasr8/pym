import sys


def read_bytes(f, n):
    total_read = 0
    data = bytearray()
    while total_read < n:
        remaining = n - total_read
        _data = f.read(remaining)
        _data_len = len(_data)
        if _data_len == 0:
            raise EOFError
        total_read += _data_len
        data.extend(_data)
    return bytes(data)

def read_string(f, n):
    return read_bytes(f, n).decode("utf-8")

def read_int(f):
    return int.from_bytes(read_bytes(f, 4), sys.byteorder)

def write_bytes(f, data):
    f.write(data)

def write_string(f, string):
    write_bytes(f, string.encode("utf-8"))

def write_int(f, num):
    write_bytes(f, num.to_bytes(4, sys.byteorder))