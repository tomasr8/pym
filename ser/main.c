#include <sys/wait.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define _PAM_GET_ITEM 1
#define _FAIL_DELAY 2
#define _PAM_GET_USER 2
#define _CONVERSE 3
#define READ_SUCCESS 0
#define ENSURE(x) if(x !== READ_SUCCESS) return x;

bool is_child;

struct ipc_pipe {
    int read_end;
    int write_end;
};

void die(char *msg) {
    perror(msg);
    _exit(EXIT_FAILURE);
}

void write_n(int fd, char *data, int n) {
    int written = write(fd, data, n);
    if(written != n) {
        die("write");
    }
}

void write_int(int fd, int n) {
    write_n(fd, (char *)&n, sizeof(int));
}

void write_string(int fd, char * str, int length) {
    write_n(fd, str, length);
}

void read_n(int fd, char *data, int n) {
    int total = 0;
    while(total != n) {
        int remaining = n - total;
        int r = read(fd, data, remaining);
        if(r <= 0) {
            die("read");
        }
        total += r;
    }
}

void read_int(int fd, int * n) {
    read_n(fd, (char *)n, sizeof(int));
}

void read_string(int fd, char * str, int length) {
    read_n(fd, str, length);
    str[length] = '\0';
}

void send_string(int fd, char *str, int len) {
    write_int(fd, len);
    write_string(fd, str, len);
}

void get_item(struct ipc_pipe p, int type, void ** out) {
    int method_type = _PAM_GET_ITEM;
    write_int(p.write_end, method_type);
    write_int(p.write_end, type);
    printf("[CH] requested item\n");

    if(type == PAM_XAUTHDATA) {
        int retval;
        struct pam_xauth_data *xauth = malloc(sizeof(struct pam_xauth_data));
        read_int(p.read_end, &retval);
        printf("[CH] retval: %d (success=%d)\n", retval, retval==PAM_SUCCESS);
        read_int(p.read_end, &xauth->namelen);
        printf("[CH] namelen: %d\n", xauth->namelen);
        xauth->name = malloc(xauth->namelen + 1);
        read_string(p.read_end, xauth->name, xauth->namelen);
        printf("[CH] name: <%s>\n", xauth->name);
        read_int(p.read_end, &xauth->datalen);
        printf("[CH] datalen: %d\n", xauth->datalen);
        xauth->data = malloc(xauth->datalen);
        read_string(p.read_end, xauth->data, xauth->datalen);
        *out = xauth;
    } else {
        int retval, length;
        read_int(p.read_end, &retval);
        printf("[CH] retval: %d (success=%d)\n", retval, retval == PAM_SUCCESS);
        read_int(p.read_end, &length);
        printf("[CH] length: %d\n", length);
        char * value = malloc(length + 1);
        read_string(p.read_end, value, length);
        *out = value;
    }

}

void send_item(struct ipc_pipe p, int item_type) {
    if(item_type == PAM_XAUTHDATA) {
        struct pam_xauth_data xauth = {
            5, "denis", 4, "XXX"
        };
        write_int(p.write_end, PAM_SUCCESS);
        write_int(p.write_end, xauth.namelen);
        write_string(p.write_end, xauth.name, xauth.namelen);
        write_int(p.write_end, xauth.datalen);
        write_string(p.write_end, xauth.data, xauth.datalen);
    } else if(item_type == PAM_USER) {
        char* username = "denis";
        write_int(p.write_end, PAM_SUCCESS);
        write_int(p.write_end, strlen(username));
        write_string(p.write_end, username, strlen(username));
    } else {
        die("[PA] unknown item type\n");
    }
}

void fail_delay_child(struct ipc_pipe p, int usec) {
    int method_type = _FAIL_DELAY;
    write_int(p.write_end, method_type);
    printf("[CH] setting fail delay\n");
    write_int(p.write_end, usec);

    int retval;
    read_int(p.read_end, &retval);
    printf("[CH] retval: %d (success=%d)\n", retval, retval == PAM_SUCCESS);
}

void fail_delay_parent(struct ipc_pipe p) {
    write_int(p.write_end, PAM_SUCCESS);
    write_int(p.write_end, 1234);
}

void get_user_child(struct ipc_pipe p, char *prompt, char ** username) {
    int method_type = _PAM_GET_USER;
    write_int(p.write_end, method_type);
    printf("[CH] getting user\n");
    if(prompt) {
        write_int(p.write_end, strlen(prompt));
        write_string(p.write_end, prompt, strlen(prompt));
    } else {
        write_int(p.write_end, 0);
    }

    int retval, len;
    read_int(p.read_end, &retval);
    printf("[CH] retval: %d (success=%d)\n", retval, retval == PAM_SUCCESS);
    read_int(p.read_end, &len);
    char *str = malloc(len + 1);
    read_string(p.read_end, str, len);
    *username = str;
}

void get_user_parent(struct ipc_pipe p) {
    int len;
    char *prompt = NULL;
    read_int(p.read_end, &len);

    if(len > 0) {
        prompt = malloc(len + 1);
        read_string(p.read_end, prompt, len);
    }

    char * username = "ken";
    write_int(p.write_end, PAM_SUCCESS);
    write_int(p.write_end, strlen(username));
    write_string(p.write_end, username, strlen(username));
    free(prompt);
}


void converse_child(struct ipc_pipe p, int num_msgs, struct pam_message ** msgs, struct pam_response **out) {
    int method_type = _CONVERSE;
    write_int(p.write_end, method_type);
    printf("[CH] converse()\n");
    write_int(p.write_end, num_msgs);

    for(int i = 0; i < num_msgs; i++) {
        struct pam_message * msg = msgs[i];
        write_int(p.write_end, msg->msg_style);
        write_int(p.write_end, strlen(msg->msg));
        write_string(p.write_end, msg->msg, strlen(msg->msg));
    }

    int retval, num_resps;
    read_int(p.read_end, &retval);
    printf("[CH] retval: %d (success=%d)\n", retval, retval == PAM_SUCCESS);
    read_int(p.read_end, &num_resps);
    struct pam_response **resps = malloc(num_resps * sizeof(struct pam_response*));

    for(int i = 0; i < num_resps; i++) {

    }

}

int main(void) {
    int parent_child[2];
    int child_parent[2];

    pipe(parent_child);
    pipe(child_parent);

    struct ipc_pipe parent = {child_parent[0], parent_child[1]};
    struct ipc_pipe child = {parent_child[0], child_parent[1]};

    int status = 2;
    ENSURE(status);

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid == 0) {            /* Code executed by child */
        printf("Child PID is %jd\n", (intmax_t) getpid());
        is_child = true;
        close(parent_child[1]);
        close(child_parent[0]);

        sleep(2);

        char * str;
        get_item(child, PAM_USER, (void**)&str);
        printf("Got username: <%s>\n", str);
        free(str);

        struct pam_xauth_data *xauth;
        get_item(child, PAM_XAUTHDATA, (void**)&xauth);
        printf("Got xauthdata: <%s, %d>\n", xauth->name, xauth->datalen);
        free(xauth->name);
        free(xauth->data);
        free(xauth);

        _exit(EXIT_SUCCESS);

    } else {                    /* Code executed by parent */
        close(parent_child[0]);
        close(child_parent[1]);
        is_child = false;

        while(true) {
            int method_type;
            read_int(parent.read_end, &method_type);
            printf("[PA] requested method: %d\n", method_type);
            if(method_type == _PAM_GET_ITEM) {
                int item_type;
                read_int(parent.read_end, &item_type);
                printf("[PA] requested item type: %d\n", item_type);
                send_item(parent, item_type);
            } else {
                die("[PA] unknown method\n");
            }
        }

        int status;
        waitpid(0, &status, 0);
    }

}
