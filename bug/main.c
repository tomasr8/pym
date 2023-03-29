// Should de defined at the beginning of a PAM module
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <stdio.h>
#include <stdbool.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <Python.h>

#include "pym.h"
#define MODULE_NAME "pym"

int main() {
    printf("main()\n");
    int n = Py_IsInitialized();
    printf("init %d\n", n);
    int err = PyImport_AppendInittab(MODULE_NAME, PyInit_pym);
    printf("Loaded module %d\n", err);
    Py_Initialize();
    printf("Importing module\n");
    PyImport_ImportModule(MODULE_NAME);

    Py_Finalize();
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("pam_sm_authenticate(): %d %d\n", flags, argc);
    int n = Py_IsInitialized();
    printf("init %d\n", n);
    int err = PyImport_AppendInittab(MODULE_NAME, PyInit_pym);
    printf("Loaded module %d\n", err);
    Py_Initialize();
    printf("Importing module\n");
    PyImport_ImportModule(MODULE_NAME);

    Py_Finalize();
    return PAM_SUCCESS;
}
