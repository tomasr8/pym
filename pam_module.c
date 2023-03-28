// Should de defined at the beginning of a PAM module
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <stdbool.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <Python.h>
#include "pam.h"

const char* module_name = "pym_python_pam_module";
// Thread-safe updates
_Atomic int n_simultaneous_requests = 0;
PyGILState_STATE gil_state;

void cleanup(pam_handle_t *pamh, void *data, int error_status) {
    n_simultaneous_requests--;
    if(n_simultaneous_requests == 0) {
        // last thread to finish running is responsible for cleaning up
        Py_FinalizeEx();
    }
}

void register_cleanup(pam_handle_t *pamh) {
    pam_set_data(pamh, module_name, NULL, cleanup);
}

void initialize(pam_handle_t *pamh) {
    // https://docs.python.org/3/c-api/init.html#non-python-created-threads
    // unlike in python2, in python3 thread management is done automatically by Py_Initialize()
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyImport_ImportModule("pam");
}

int handle_request(pam_handle_t *pamh, int flags, int argc, const char **argv, const char *pam_fn_name, int err_return) {
    n_simultaneous_requests++;
    register_cleanup(pamh);
    if(!Py_IsInitialized()) {
        initialize(pamh);
    }

    gil_state = PyGILState_Ensure();
    int retval = python_handle_request(pamh, flags, argc, argv, pam_fn_name);
    PyGILState_Release(gil_state);

    if(PyErr_Occurred() != NULL) {
        return err_return;
    }
    return retval;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, "pam_sm_authenticate", PAM_AUTH_ERR);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, "pam_sm_setcred", PAM_CRED_ERR);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, "pam_sm_acct_mgmt", PAM_AUTH_ERR);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, "pam_sm_open_session", PAM_SESSION_ERR);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, "pam_sm_close_session", PAM_SESSION_ERR);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, "pam_sm_chauthtok", PAM_AUTHTOK_ERR);
}
