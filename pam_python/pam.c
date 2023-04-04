#include "pam.h"

#define ENSURE(x) \
  if (x != SUCCESS) return x
#define ENSURE(x, ret) \
  if (x != SUCCESS) return ret


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


int get_error_description(pam_handle_t *pamh, struct ipc_pipe p) {
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


int get_item(pam_handle_t *pamh, struct ipc_pipe p) {
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


int set_item(pam_handle_t *pamh, struct ipc_pipe p) {
  int item_type;
  int status = read_int(p.read_end, &item_type);
  ENSURE(status);

  if (item_type == PAM_XAUTHDATA) {
    struct pam_xauth_data *xauth = malloc(sizeof(struct pam_xauth_data));
    if (!xauth) return MALLOC_ERR;

    status = read_int(p.read_end, &xauth->namelen);
    if (status != SUCCESS) goto cleanup;

    xauth->name = malloc(xauth->namelen + 1);
    if (!xauth->name) {
        status = MALLOC_ERR;
        goto cleanup;
    }

    status = read_string(p.read_end, name, xauth->namelen);
    if (status != SUCCESS) goto cleanup;

    status = read_int(p.read_end, &xauth->datalen);
    if (status != SUCCESS) goto cleanup;

    xauth->data = malloc(xauth->datalen);
    if (xauth->data) {
        status = MALLOC_ERR;
        goto cleanup;
    }

    status = read_bytes(p.read_end, data, xauth->datalen);
    if (status != SUCCESS) goto cleanup;

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
    ENSURE(status);

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

int fail_delay(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, delay;

  status = read_int(p.read_end, &delay);
  ENSURE(status);

  int retval = pam_fail_delay(pamh, delay);
  status = write_int(p.write_end, retval);
  ENSURE(status);

  return SUCCESS;
}

int converse(pam_handle_t *pamh, struct ipc_pipe p) {
  int status, retval, num_msgs;
  struct pam_conv *conv;
  
  status = read_int(p.read_end, &num_msgs);
  ENSURE(status);

  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS) {
    status = write_int(p.write_end, retval);
    return status;
  }

  struct pam_message **msgs = malloc(num_msgs * sizeof(struct pam_message *));
  if(!pam_message) {
    return MALLOC_ERR;
  }

  for (int i = 0; i < num_msgs; i++) {
    msgs[i] = malloc(sizeof(struct pam_message));
    status = read_int(p.read_end, &msgs[i]->msg_style);
    int len;
    status = read_int(p.read_end, &len);
    msgs[i]->msg = malloc(len + 1);
    status = read_string(p.read_end, (char *)msgs[i]->msg, len);
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

//   for (int i = 0; i < num_msgs; i++) {
//     free((char *)msgs[i]->msg);
//     free(msgs[i]);
//   }
//   free(msgs);

  status = write_int(p.write_end, PAM_SUCCESS);

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


cleanup:
  for (int i = 0; i < num_msgs; i++) {
    if(msgs[i]) {
        if(msgs[i]->msg) free(msgs[i]->msg);
        free(msgs[i]);
    }
  }
  free(msgs);
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

// static void _log(pamh, int priority, )
