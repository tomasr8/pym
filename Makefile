cython3 -o pam.c pam.pyx
gcc -Os -I /usr/include/python3.9 -o pam main.c pam.c -lpython3.9 -lpthread -lm -lutil -ldl -lpam

gcc -O2 -I /usr/include/python3.9 -o pam.so pam.c -lpython3.9 -lpthread -lm -lutil -ldl -lpam -shared -fPIC -fwrapv -fno-strict-aliasing

python3.8-config --ldflags
