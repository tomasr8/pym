from dataclasses import dataclass

cdef extern from "class_test.h":
    cdef int _XXX "XXX"

@dataclass
class Message:
    msg_style: int
    msg: str

    # __annotations__ = {
    #     'msg_style': int,
    #     'msg': str,
    # }

class Test:
    XXX = _XXX
