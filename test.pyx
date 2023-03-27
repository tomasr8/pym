class Test:
    a = 7

cdef class Child(Test):
    cdef int x


c = Child()
