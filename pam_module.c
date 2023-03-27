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
// bool initialized = false;
int n_simultaneous_requests = 0;
PyGILState_STATE gil_state;

void register_cleanup(pam_handle_t *pamh) {
    pam_set_data(pamh, module_name, NULL, cleanup);
}

void initialize(pam_handle_t *pamh) {
    register_cleanup(pamh);
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyImport_ImportModule("pam");
}

void cleanup(pam_handle_t *pamh, void *data, int error_status) {
    n_simultaneous_requests--;
    Py_FinalizeEx();
    // initialized = false;
}

int handle_request(pam_handle_t *pamh, int flags, int argc, const char **argv, int (*fn)(pam_handle_t *, int, int, char const **)) {
    n_simultaneous_requests++;
    if(!Py_IsInitialized()) {
        initialize(pamh);
    }
    gil_state = PyGILState_Ensure();
    int retval = fn(pamh, flags, argc, argv);
    PyGILState_Release(gil_state);
    if(PyErr_Occurred() != NULL) {
        return PAM_AUTH_ERR;
    }
    return retval;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, pym_authenticate);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, pym_authenticate);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, pym_authenticate);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, pym_authenticate);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, pym_authenticate);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return handle_request(pamh, flags, argc, argv, pym_authenticate);
}
