#include "pam.h"

#define OK(x) \
  if (x != SUCCESS) return x

#define OK_GOTO(x) \
  if (x != SUCCESS) goto cleanup

int get_default_err(char *pam_fn_name) {
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

int ipc_strerror(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, errnum;

  status = read_int(p.read_end, &errnum);
  OK(status);

  const char *str = pam_strerror(pamh, errnum);

  status = write_int(p.write_end, strlen(str));
  OK(status);

  status = write_string(p.write_end, (char *)str, strlen(str));
  OK(status);

  return SUCCESS;
}

int ipc_get_item(pam_handle_t *pamh, struct ipc_pipe p) {
  int item_type;
  int status = read_int(p.read_end, &item_type);
  OK(status);

  if (item_type == PAM_XAUTHDATA) {
    struct pam_xauth_data *xauth;

    int retval = pam_get_item(pamh, item_type, (const void **)&xauth);
    status = write_int(p.write_end, retval);
    OK(status);

    if (pam_retval == PAM_SUCCESS) {
      status = write_int(p.write_end, xauth->namelen);
      OK(status);
      status = write_string(p.write_end, xauth->name, xauth->namelen);
      OK(status);
      status = write_int(p.write_end, xauth->datalen);
      OK(status);
      status = write_string(p.write_end, xauth->data, xauth->datalen);
      OK(status);
    }

    return SUCCESS;
  } else {
    char *item;

    retval = pam_get_item(pamh, item_type, (const void **)&item);
    status = write_int(p.write_end, retval);
    OK(status);

    if (retval == PAM_SUCCESS) {
      status = write_int(p.write_end, strlen(item));
      OK(status);
      status = write_string(p.write_end, item, strlen(item));
      OK(status);
    }

    return SUCCESS;
  }
}

int ipc_set_item(pam_handle_t *pamh, struct ipc_pipe p) {
  int item_type;
  int status = read_int(p.read_end, &item_type);
  OK(status);

  if (item_type == PAM_XAUTHDATA) {
    struct pam_xauth_data *xauth = malloc(sizeof(struct pam_xauth_data));
    if (!xauth) return MALLOC_ERR;

    status = read_int(p.read_end, &xauth->namelen);
    OK_GOTO(status);

    xauth->name = malloc(xauth->namelen + 1);
    if (!xauth->name) {
      status = MALLOC_ERR;
      goto cleanup;
    }

    status = read_string(p.read_end, name, xauth->namelen);
    OK_GOTO(status);

    status = read_int(p.read_end, &xauth->datalen);
    OK_GOTO(status);

    xauth->data = malloc(xauth->datalen);
    if (xauth->data) {
      status = MALLOC_ERR;
      goto cleanup;
    }

    status = read_bytes(p.read_end, data, xauth->datalen);
    OK_GOTO(status);

    int retval = pam_set_item(pamh, item_type, xauth);
    status = write_int(p.write_end, retval);

  cleanup:
    if (xauth->name) free(xauth->name);
    if (xauth->data) free(xauth->data);
    if (xauth) free(xauth);
    return status;
  } else {
    int len;

    status = read_int(p.read_end, &len);
    OK(status);

    char *item = malloc(len + 1);
    if (!item) return MALLOC_ERR;

    status = read_string(p.read_end, item, len);
    if (status != SUCCESS) {
      free(item);
      return status;
    }

    int retval = pam_set_item(pamh, item_type, (const void *)item);
    status = write_int(p.write_end, retval);
    free(item);
    return status;
  }
}

int ipc_fail_delay(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, delay;

  status = read_int(p.read_end, &delay);
  OK(status);

  int retval = pam_fail_delay(pamh, delay);
  status = write_int(p.write_end, retval);
  OK(status);

  return SUCCESS;
}

int ipc_converse(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, retval, num_msgs;
  struct pam_conv *conv;

  status = read_int(p.read_end, &num_msgs);
  OK(status);

  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS) {
    status = write_int(p.write_end, retval);
    return status;
  }

  struct pam_message **msgs = malloc(num_msgs * sizeof(struct pam_message *));
  if (!pam_message) {
    return MALLOC_ERR;
  }

  int len;
  for (int i = 0; i < num_msgs; i++) {
    msgs[i] = malloc(sizeof(struct pam_message));
    if (!msgs[i]) goto cleanup;

    status = read_int(p.read_end, &msgs[i]->msg_style);
    OK_GOTO(status);
    status = read_int(p.read_end, &len);
    OK_GOTO(status);

    msgs[i]->msg = malloc(len + 1);
    if (!msgs[i]->msg) goto cleanup;

    status = read_string(p.read_end, (char *)msgs[i]->msg, len);
    OK_GOTO(status);
  }

  struct pam_response *resps;
  retval = conv->conv(num_msgs, (const struct pam_message **)msgs, &resps, conv->appdata_ptr);
  if (retval != PAM_SUCCESS) {
    write_int(p.write_end, retval);
    goto cleanup;
  }

  status = write_int(p.write_end, PAM_SUCCESS);
  OK_GOTO(status);

  for (int i = 0; i < num_msgs; i++) {
    status = write_int(p.write_end, resps[i].resp_retcode);
    OK_GOTO(status);

    if (!resps[i].resp) {
      status = write_int(p.write_end, 0);
      OK_GOTO(status);
    } else {
      int len = strlen(resps[i].resp);

      status = write_int(p.write_end, len);
      OK_GOTO(status);

      status = write_string(p.write_end, resps[i].resp, len);
      OK_GOTO(status);
    }
  }

cleanup:
  for (int i = 0; i < num_msgs; i++) {
    if (msgs[i]) {
      if (msgs[i]->msg) free(msgs[i]->msg);
      free(msgs[i]);
    }
  }
  free(msgs);

  // We are responsible for freeing the responses
  if (resps) {
    for (int i = 0; i < num_msgs; i++) {
      if (resps[i].resp) {
        int len = strlen(resps[i].resp);
        // Overwriting ensures we don't leak any sensitive data like passwords
        memset(resps[i].resp, 0, len);
        free(resps[i].resp);
      }
    }
    free(resps);
  }

  return status;
}

int ipc_syslog(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, priority, len;
  char *msg;

  status = read_int(p.read_end, &priority);
  OK(status);

  status = read_int(p.read_end, &len);
  OK(status);

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