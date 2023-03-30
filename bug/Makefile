cython -o pym.c -3 pym.pyx

gcc -O2 -I /usr/include/python3.9 -o main.so pym.c main.c -lpython3.9 -lpam -lpthread -lm -lutil -ldl -shared -fPIC -fwrapv -fno-strict-aliasing
