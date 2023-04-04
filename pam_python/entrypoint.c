// Should de defined at the beginning of a PAM module
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include "pam_python.h"
#include "pam.h"

static char libpython_so[] = LIBPYTHON_SO;

static int _converse(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
  struct pam_response *aresp;
  char buf[PAM_MAX_RESP_SIZE];
  int i;

  data = data;
  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return (PAM_CONV_ERR);
  if ((aresp = calloc(n, sizeof *aresp)) == NULL)
    return (PAM_BUF_ERR);
  for (i = 0; i < n; ++i) {
    aresp[i].resp_retcode = 0;
    aresp[i].resp = NULL;
    switch (msg[i]->msg_style) {
      case PAM_PROMPT_ECHO_OFF:
        aresp[i].resp = strdup(getpass(msg[i]->msg));
        if (aresp[i].resp == NULL)
          goto fail;
        break;
      case PAM_PROMPT_ECHO_ON:
        fputs(msg[i]->msg, stderr);
        if (fgets(buf, sizeof buf, stdin) == NULL)
          goto fail;
        aresp[i].resp = strdup(buf);
        if (aresp[i].resp == NULL)
          goto fail;
        break;
      case PAM_ERROR_MSG:
        fputs(msg[i]->msg, stderr);
        if (strlen(msg[i]->msg) > 0 &&
            msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
          fputc('\n', stderr);
        break;
      case PAM_TEXT_INFO:
        fputs(msg[i]->msg, stdout);
        if (strlen(msg[i]->msg) > 0 &&
            msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
          fputc('\n', stdout);
        break;
      default:
        goto fail;
    }
  }
  *resp = aresp;
  return (PAM_SUCCESS);
fail:
  for (i = 0; i < n; ++i) {
    if (aresp[i].resp != NULL) {
      memset(aresp[i].resp, 0, strlen(aresp[i].resp));
      free(aresp[i].resp);
    }
  }
  memset(aresp, 0, n * sizeof *aresp);
  *resp = NULL;
  return (PAM_CONV_ERR);
}

static void execute_child(struct ipc_pipe child, int flags, int argc, char const **argv, char *pam_fn_name) {
  const int err_return = get_default_err(pam_fn_name);
  // ??? why do I need to acquire the gil????
  PyGILState_STATE gil_state;
  if (Py_IsInitialized()) {
    PyGILState_Ensure();
    Py_FinalizeEx();
  }

  PyImport_AppendInittab("pam_python", PyInit_pam_python);
  Py_Initialize();
  gil_state = PyGILState_Ensure();

  printf("PyImport_ImportModule\n");
  PyObject *module = PyImport_ImportModule("pam_python");
  if (module == NULL) {
    printf("PyImport_ImportModule failed..\n");
    PyGILState_Release(gil_state);
    _exit(err_return);
  }

  int retval = python_handle_request(child.read_end, child.write_end, flags, argc, argv, pam_fn_name);
  if (PyErr_Occurred()) {
    retval = err_return;
  }

  PyGILState_Release(gil_state);
  Py_FinalizeEx();
  _exit(retval);
}

static int execute_parent(pam_handle_t *pamh, struct ipc_pipe parent, char *pam_fn_name) {
  const int err_return = get_default_err(pam_fn_name);
  while (true) {
    int status, method_type;

    status = read_int(parent.read_end, &method_type);

    if (status == READ_EOF) {
      return PAM_SUCCESS;
    } else if (status != SUCCESS) {
      return err_return;
    }

    if (method_type == PAM_PYTHON_GET_ITEM) {
      status = ipc_get_item(pamh, parent);
    } else if (method_type == PAM_PYTHON_SET_ITEM) {
      status = ipc_set_item(pamh, parent);
    } else if (method_type == PAM_PYTHON_FAIL_DELAY) {
      status = ipc_fail_delay(pamh, parent);
    } else if (method_type == PAM_PYTHON_CONVERSE) {
      status = ipc_converse(pamh, parent);
    } else if (method_type == PAM_PYTHON_STRERROR) {
      status = ipc_strerror(pamh, parent);
    } else if (method_type == PAM_PYTHON_SYSLOG) {
      status = ipc_syslog(pamh, parent);
    } else {
      pam_syslog(pamh, LOG_ERR, "Unknown method type: %d", method_type);
      return err_return;
    }

    if (status != SUCCESS) {
      return err_return;
    }
  }
}

int handle_request(char *pam_fn_name, pam_handle_t *pamh, int flags, int argc, char const **argv) {
  const int err_return = get_default_err(pam_fn_name);
  struct pam_conv pamc;
  pamc.conv = _converse;

  pam_set_item(pamh, PAM_CONV, &pamc);

  int parent_child[2];
  int child_parent[2];

  pipe(parent_child);
  pipe(child_parent);

  struct ipc_pipe parent = {child_parent[0], parent_child[1]};
  struct ipc_pipe child = {parent_child[0], child_parent[1]};

  int pid = fork();
  if (pid == -1) {
    pam_syslog(pamh, LOG_ERR, "Failed to fork: %s", strerror(errno));
    return err_return;
  }

  if (pid == 0) {
    close(parent_child[1]);
    close(child_parent[0]);

    execute_child(child, flags, argc, argv, pam_fn_name);
  } else {
    close(parent_child[0]);
    close(child_parent[1]);

    const ret_parent = execute_parent(pamh, parent);

    int ret_child;
    waitpid(0, &ret_child, 0);

    if (ret_parent != PAM_SUCCESS) {
      return ret_parent;
    } else {
      return ret_child;
    }
  }
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return handle_request("pam_sm_authenticate", pamh, flags, argc, argv);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return handle_request("pam_sm_setcred", pamh, flags, argc, argv);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return handle_request("pam_sm_acct_mgmt", pamh, flags, argc, argv);
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return handle_request("pam_sm_open_session", pamh, flags, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return handle_request("pam_sm_close_session", pamh, flags, argc, argv);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return handle_request("pam_sm_chauthtok", pamh, flags, argc, argv);
}
