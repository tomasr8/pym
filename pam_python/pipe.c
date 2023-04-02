#include "pipe.h"

int write_bytes(int fd, char *data, int n) {
  int written = write(fd, data, n);
  if (written != n) {
    return WRITE_ERR;
  }
}

int write_int(int fd, int n) {
  return write_bytes(fd, (char *)&n, sizeof(int));
}

int write_string(int fd, char *str, int length) {
  return write_bytes(fd, str, length);
}

int read_bytes(int fd, char *data, int n) {
  int total = 0;
  while (total != n) {
    int remaining = n - total;
    int r = read(fd, data, remaining);
    if (r == 0) {
      return EOF;
    } else if (r < 0) {
      return READ_ERR;
    }
    total += r;
  }
  return SUCCESS;
}

int read_int(int fd, int *n) {
  return read_bytes(fd, (char *)n, sizeof(int));
}

int read_string(int fd, char *str, int length) {
  int status = read_bytes(fd, str, length);
  str[length] = '\0';
  return status;
}