// Should de defined at the beginning of a PAM module
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <Python.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "pam_python.h"
#include "pipe.h"

#define ENSURE(x) \
  if (x != SUCCESS) return x
#define ENSURE(x, ret) \
  if (x != SUCCESS) return ret

static char libpython_so[] = LIBPYTHON_SO;

static int get_default_err(char *pam_fn_name) {
  if (strcmp(pam_fn_name, "pam_sm_authenticate") == 0) {
    return PAM_AUTH_ERR;
  } else if (strcmp(pam_fn_name, "pam_sm_setcred") == 0) {
    return PAM_CRED_ERR;
  } else if (strcmp(pam_fn_name, "pam_sm_acct_mgmt") == 0) {
    return PAM_AUTH_ERR;
  } else if (strcmp(pam_fn_name, "pam_sm_open_session") == 0) {
    return PAM_SESSION_ERR;
  } else if (strcmp(pam_fn_name, "pam_sm_close_session") == 0) {
    return PAM_SESSION_ERR;
  } else if (strcmp(pam_fn_name, "pam_sm_chauthtok") == 0) {
    return PAM_AUTH_ERR;
  }
  return PAM_ABORT;
}

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

static int get_item(pam_handle_t *pamh, struct ipc_pipe p) {
  int item_type;
  int status = read_int(p.read_end, &item_type);
  ENSURE(status);

  if (item_type == PAM_XAUTHDATA) {
    struct pam_xauth_data *xauth;

    int retval = pam_get_item(pamh, item_type, (const void **)&xauth);
    status = write_int(p.write_end, retval);
    ENSURE(status);

    if (pam_retval == PAM_SUCCESS) {
      status = write_int(p.write_end, xauth->namelen);
      ENSURE(status);
      status = write_string(p.write_end, xauth->name, xauth->namelen);
      ENSURE(status);
      status = write_int(p.write_end, xauth->datalen);
      ENSURE(status);
      status = write_string(p.write_end, xauth->data, xauth->datalen);
      ENSURE(status);
    }

    return SUCCESS;
  } else {
    char *item;

    retval = pam_get_item(pamh, item_type, (const void **)&item);
    status = write_int(p.write_end, retval);
    ENSURE(status);

    if (retval == PAM_SUCCESS) {
      status = write_int(p.write_end, strlen(item));
      ENSURE(status);
      status = write_string(p.write_end, item, strlen(item));
      ENSURE(status);
    }

    return SUCCESS;
  }
}

static int set_item(pam_handle_t *pamh, struct ipc_pipe p) {
  int item_type;
  int status = read_int(p.read_end, &item_type);
  ENSURE(retval);

  if (item_type == PAM_XAUTHDATA) {
    struct pam_xauth_data *xauth = malloc(sizeof(struct pam_xauth_data));
    if (!xauth) return MALLOC_ERR;

    status = read_int(p.read_end, &xauth->namelen);
    if (status != SUCCESS) goto cleanup;

    char *name = malloc(xauth->namelen + 1);
    status = read_string(p.read_end, name, xauth->namelen);
    if (status != SUCCESS) goto cleanup;
    xauth->name = name;

    status = read_int(p.read_end, &xauth->datalen);
    if (status != SUCCESS) goto cleanup;

    char *data = malloc(xauth->datalen);
    status = read_bytes(p.read_end, data, xauth->datalen);
    if (status != SUCCESS) goto cleanup;
    xauth->data = data;

    int retval = pam_set_item(pamh, item_type, xauth);
    status = write_int(p.write_end, retval);

  cleanup:
    if (item) free(name);
    if (data) free(data);
    if (xauth) free(xauth);
    return status;
  } else {
    int len;

    status = read_int(p.read_end, &len);
    ENSURE(status);

    char *item = malloc(len + 1);
    if (!item) return MALLOC_ERR;

    status = read_string(p.read_end, item, len);
    if (status != PAM_SUCCESS) {
      free(item);
      return status;
    }

    int retval = pam_set_item(pamh, item_type, (const void *)item);
    status = write_int(p.write_end, retval);
    return status;
  }
}

static enum Status set_fail_delay(pam_handle_t *pamh, struct ipc_pipe p) {
  int delay;
  enum Status status;

  read_int(p.read_end, &delay);
  ENSURE(status);

  int retval = pam_fail_delay(pamh, delay);

  status = write_int(p.write_end, retval);
  ENSURE(status);

  return SUCCESS;
}

static int converse(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, retval, num_msgs;
  read_int(p.read_end, &num_msgs);
  struct pam_conv *conv;

  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS) {
    status = write_int(p.write_end, retval);
    return status;
  }

  struct pam_message **msgs = malloc(num_msgs * sizeof(struct pam_message *));
  for (int i = 0; i < num_msgs; i++) {
    msgs[i] = malloc(sizeof(struct pam_message));
    read_int(p.read_end, &msgs[i]->msg_style);
    int len;
    read_int(p.read_end, &len);
    msgs[i]->msg = malloc(len + 1);
    read_string(p.read_end, (char *)msgs[i]->msg, len);
  }

  struct pam_response *resps;
  retval = conv->conv(num_msgs, (const struct pam_message **)msgs, &resps, conv->appdata_ptr);
  if (retval != PAM_SUCCESS) {
    write_int(p.write_end, retval);
    for (int i = 0; i < num_msgs; i++) {
      free((char *)msgs[i]->msg);
      free(msgs[i]);
    }
    free(msgs);
    return;
  }

  for (int i = 0; i < num_msgs; i++) {
    free((char *)msgs[i]->msg);
    free(msgs[i]);
  }
  free(msgs);

  write_int(p.write_end, PAM_SUCCESS);

  for (int i = 0; i < num_msgs; i++) {
    write_int(p.write_end, resps[i].resp_retcode);
    if (!resps[i].resp) {
      write_int(p.write_end, 0);
    } else {
      int len = strlen(resps[i].resp);
      write_int(p.write_end, len);
      write_string(p.write_end, resps[i].resp, len);
      // We are responsible for freeing the responses
      // # Overwrite and free the response
      // # Overwriting ensures we don't leak any sensitive data like passwords
      memset(resps[i].resp, 0, len);
      free(resps[i].resp);
    }
  }
  free(resps);
}

static int get_error_description(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, errnum;

  status = read_int(p.read_end, &errnum);
  ENSURE(status);

  const char *str = pam_strerror(pamh, errnum);

  status = write_int(p.write_end, strlen(str));
  ENSURE(status);

  status = write_string(p.write_end, (char *)str, strlen(str));
  ENSURE(status);

  return SUCCESS;
}

static int log_to_syslog(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, priority, len;
  char *msg;

  status = read_int(p.read_end, &priority);
  ENSURE(status);

  status = read_int(p.read_end, &len);
  ENSURE(status);

  msg = malloc(len + 1);
  if (!msg) return MALLOC_ERR;

  status = read_string(p.read_end, msg, len);
  if (status != SUCCESS) {
    free(msg);
    return status;
  }

  pam_syslog(pamh, priority, "%s", msg);

  free(msg);
  return SUCCESS;
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

    if (method_type == _PAM_METHOD_GET_ITEM) {
      get_item(pamh, parent);
    } else if (method_type == _PAM_METHOD_SET_ITEM) {
      set_item(pamh, parent);
    } else if (method_type == _PAM_METHOD_FAIL_DELAY) {
      set_fail_delay(pamh, parent);
    } else if (method_type == _PAM_METHOD_CONVERSE) {
      converse(pamh, parent);
    } else if (method_type == _PAM_METHOD_STRERROR) {
      status = get_error_description(pamh, parent);
      ENSURE(status, err_return);
    } else if (method_type == _PAM_METHOD_SYSLOG) {
      status = log_to_syslog(pamh, parent);
      ENSURE(status, err_return);
    } else {
      pam_syslog(pamh, LOG_ERR, "Unknown method type: %d", method_type);
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

  if (pid == 0) { /* Code executed by child */
    close(parent_child[1]);
    close(child_parent[0]);
    execute_child(child, flags, argc, argv, pam_fn_name);
  } else {
    close(parent_child[0]);
    close(child_parent[1]); /* Code executed by parent */

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
