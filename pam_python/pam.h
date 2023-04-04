#ifndef _PAM_PYTHON_PAM_H
#define _PAM_PYTHON_PAM_H

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

#include "pipe.h"

#define PAM_PYTHON_GET_ITEM   1
#define PAM_PYTHON_SET_ITEM   2
#define PAM_PYTHON_GET_USER   3
#define PAM_PYTHON_CONVERSE   4
#define PAM_PYTHON_FAIL_DELAY 5
#define PAM_PYTHON_STRERROR   6
#define PAM_PYTHON_SYSLOG     7

int get_default_err(char *pam_fn_name);

int ipc_strerror(pam_handle_t *pamh, struct ipc_pipe p);

int ipc_get_item(pam_handle_t *pamh, struct ipc_pipe p);

int ipc_set_item(pam_handle_t *pamh, struct ipc_pipe p);

int ipc_fail_delay(pam_handle_t *pamh, struct ipc_pipe p);

int ipc_converse(pam_handle_t *pamh, struct ipc_pipe p);

int ipc_syslog(pam_handle_t *pamh, struct ipc_pipe p);

#endif