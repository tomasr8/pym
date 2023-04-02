// Should de defined at the beginning of a PAM module
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <sys/wait.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <Python.h>

#include "pam_python.h"

#define MODULE_NAME "pam_python.pam_python"

static char libpython_so[] = LIBPYTHON_SO;

// Thread-safe updates
// _Atomic int n_simultaneous_requests = 0;

// void cleanup(pam_handle_t *pamh, void *data, int error_status) {
//     n_simultaneous_requests--;
//     if(n_simultaneous_requests == 0) {
//         // last thread to finish running is responsible for cleaning up
//         Py_FinalizeEx();
//     }
// }

// void register_cleanup(pam_handle_t *pamh) {
//     pam_set_data(pamh, MODULE_NAME, NULL, cleanup);
// }

// void initialize(pam_handle_t *pamh) {
//     // https://docs.python.org/3/c-api/init.html#non-python-created-threads
//     // unlike in python2, in python3 thread management is done automatically by Py_Initialize()
//     printf("here\n");
//     PyImport_AppendInittab(MODULE_NAME, PyInit_pam_python);
//     printf("here2\n");
    
//     Py_Initialize();
//     printf("here3\n");

//     PyGILState_STATE gil_state = PyGILState_Ensure();
//     printf("here4\n");
    
//     PyImport_ImportModule(MODULE_NAME);
//     printf("here5\n");

//     PyGILState_Release(gil_state);
//     printf("here6\n");

// }

static void generic_dealloc(PyObject* self)
{
  PyTypeObject*		type = self->ob_type;

  if (PyObject_IS_GC(self))
    PyObject_GC_UnTrack(self);
  if (type->tp_clear != 0)
    type->tp_clear(self);
  type->tp_free(self);
}

int handle_request(pam_handle_t *pamh, int flags, int argc, char const **argv, char *pam_fn_name, int err_return) {
    PyGILState_STATE gil_state = PyGILState_Ensure();
    PyThreadState* pGlobalThreadState = PyThreadState_Get();
    PyThreadState* pInterpreterThreadState = Py_NewInterpreter();
    PyThreadState_Swap(pInterpreterThreadState);

    // PyObject* pyModule = PyInit_pam_python();
    // Py_DECREF(pyModule);
    // PyObject_GC_UnTrack(pyModule);

    printf("here\n");
    // PyImport_AddModule("pam_python");
    // PyObject *def = PyInit_pam_python();
    // if (!def) {
    //     PyErr_Print();
    //     exit(1);
    // }
    // PyObject *spec = PyObject_GetAttrString(def, "__spec__");
    // PyObject *module = PyModule_FromDefAndSpec(def, spec);
    // PyModule_ExecDef(module, def);

    // PyImport_AppendInittab("pam_python", PyInit_pam_python);
    // PyImport_AddModule("pam_python");
    PyObject* pyModule = PyInit_pam_python();
    if (!pyModule) {
        PyErr_Print();
        exit(1);
    }
    Py_INCREF(pyModule);
    PyObject* sys_modules = PyImport_GetModuleDict();
    if (!sys_modules) {
        PyErr_Print();
        exit(1);
    }
    printf("here2\n");
    PyDict_SetItemString(sys_modules, "pam_python", pyModule);
    // Py_XDECREF(pyModule);
    printf("here2.5\n");
    // PyRun_SimpleString("print('Inside new interp')"); // Importing PySide deadlocks
    // python_handle_request(pamh, flags, argc, argv, pam_fn_name);
    // printf("function returned\n");

    printf("here3\n");
    // generic_dealloc(pyModule);

    Py_EndInterpreter(pInterpreterThreadState);
    printf("swapped interp\n");

    PyThreadState_Swap(pGlobalThreadState);
    printf("releasing gil..\n");

    if(gil_state) {
        PyGILState_Release(gil_state);
    }
    printf("gil releasesd\n");

    return PAM_SUCCESS;



    // ==========================================================


    // printf("Forking...\n");

    // pid_t cpid, w;
    // int wstatus;

    // cpid = fork();
    // if (cpid == -1) {
    //     perror("fork");
    //     return PAM_ABORT;
    // }

    // if (cpid == 0) {            /* Code executed by child */
    //     printf("Child PID is %jd\n", (intmax_t) getpid());

    //     printf("here\n");
    //     // ??? why do I need to acquire the gil????
    //     PyGILState_STATE gil_state = PyGILState_Ensure();

    //     Py_FinalizeEx();
    //     PyImport_AppendInittab("pam_python", PyInit_pam_python);
    //     Py_Initialize();
    //     gil_state = PyGILState_Ensure();

    //     printf("PyImport_ImportModule\n");
    //     PyObject* module = PyImport_ImportModule("pam_python");
    //     if(module == NULL) {
    //         printf("PyImport_ImportModule failed..\n");
    //         PyGILState_Release(gil_state);
    //         return PAM_ABORT;
    //     }

    //     python_handle_request(pamh, flags, argc, argv, pam_fn_name);

    //     PyGILState_Release(gil_state);
    //     Py_FinalizeEx();
    //     exit(PAM_SUCCESS);

    // } else {                    /* Code executed by parent */
    //     do {
    //         w = waitpid(cpid, &wstatus, WUNTRACED | WCONTINUED);
    //         if (w == -1) {
    //             perror("waitpid");
    //             return PAM_ABORT;
    //         }

    //         if (WIFEXITED(wstatus)) {
    //             printf("exited, status=%d\n", WEXITSTATUS(wstatus));
    //         } else if (WIFSIGNALED(wstatus)) {
    //             printf("killed by signal %d\n", WTERMSIG(wstatus));
    //         } else if (WIFSTOPPED(wstatus)) {
    //             printf("stopped by signal %d\n", WSTOPSIG(wstatus));
    //         } else if (WIFCONTINUED(wstatus)) {
    //             printf("continued\n");
    //         }
    //     } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));
    //     return PAM_SUCCESS;
    // }

    // printf("HANDLING REQUEST\n");
    // n_simultaneous_requests++;
    // printf("Increased reqeusts\n");
    // register_cleanup(pamh);
    // printf("registered cleanup\n");
    // // if(!Py_IsInitialized()) {
    // //     initialize(pamh);
    // // }

    // printf("aqcuiring lock\n");

    // PyGILState_STATE gil_state = PyGILState_Ensure();
    // printf("PyImport_AppendInittab\n");
    
    // int ret = PyImport_AppendInittab("pam_python", PyInit_pam_python);
    // printf("ret: %d\n", ret);
    // printf("PyImport_ImportModule\n");
    // PyObject* module = PyImport_ImportModule("pam_python");
    // if(module == NULL) {
    //     printf("PyImport_ImportModule failed..\n");
    //     PyGILState_Release(gil_state);
    //     return PAM_ABORT;
    // }

    // printf("calling module././\n");

    // int retval = python_handle_request(pamh, flags, argc, argv, pam_fn_name);
    // PyGILState_Release(gil_state);

    // if(PyErr_Occurred() != NULL) {
    //     return err_return;
    // }
    // return retval;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("Hello from pam! %s\n", libpython_so);
    handle_request(pamh, flags, argc, argv, "pam_sm_authenticate", PAM_AUTH_ERR);
    printf("handled\n");

    if(PyErr_Occurred()) {
        printf("ERRRRRR\n");
        PyErr_Print();
    }
    return PAM_SUCCESS;
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
