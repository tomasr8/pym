#ifndef _PAM_PYTHON_PIPE_H
#define _PAM_PYTHON_PIPE_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _PAM_METHOD_GET_ITEM 1
#define _PAM_METHOD_SET_ITEM 2
#define _PAM_METHOD_GET_USER 3
#define _PAM_METHOD_CONVERSE 4
#define _PAM_METHOD_FAIL_DELAY 5
#define _PAM_METHOD_STRERROR 6
#define _PAM_METHOD_SYSLOG 7

#define SUCCESS 0
#define READ_EOF 1
#define READ_ERR 2
#define WRITE_ERR 3
#define MALLOC_ERR 4

struct ipc_pipe {
  int read_end;
  int write_end;
};

int write_bytes(int fd, char *data, int n);
int write_int(int fd, int n);
int write_string(int fd, char *str, int length);

int read_bytes(int fd, char *data, int n);
int read_int(int fd, int *n);
int read_string(int fd, char *str, int length);

#endif