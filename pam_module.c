#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <Python.h>

#include "pam.h"

const char* module_name = "pym_python_pam_module";

void cleanup(pam_handle_t *pamh, void *data, int error_status) {
    Py_FinalizeEx();
}

int inititalize_python() {
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_set_data(pamh, module_name, NULL, cleanup);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    return pym_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_set_data(pamh, module_name, NULL, cleanup);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    return pym_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_set_data(pamh, module_name, NULL, cleanup);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    return pym_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_set_data(pamh, module_name, NULL, cleanup);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    return pym_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_set_data(pamh, module_name, NULL, cleanup);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    return pym_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_set_data(pamh, module_name, NULL, cleanup);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    return pym_authenticate(pamh, flags, argc, argv);
}
