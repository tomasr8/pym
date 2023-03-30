#define _XOPEN_SOURCE 700
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
    void *handle;
    int (*a)(void);
    int (*b)(void);
    char *error;

    // handle = dlopen("/home/troun/Desktop/pym/bug/main.so", RTLD_LAZY);
    handle = dlopen("/home/troun/Desktop/pym/bug/pam_python3.so", RTLD_NOW);

    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror();
    a = (int (*)(void)) dlsym(handle, "run_python");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }
    printf("Calling function \n");
    a();
    dlclose(handle);
    return EXIT_SUCCESS;
}
