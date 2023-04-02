import ctypes


# sh_obj = ctypes.cdll.LoadLibrary('./pym.so')
# print(sh_obj.PyInit_pym)
# print(sh_obj.PyInit_pym())
# print(sh_obj.print_hello())

# import pym
# pym.print_hello()

sh_obj = ctypes.cdll.LoadLibrary('./main.so')
sh_obj.test()
