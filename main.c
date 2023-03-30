#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>


#include <Python.h>
#include "pam.h"

static pam_handle_t *pamh;
static struct pam_conv pamc;

// int converse(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
//     printf("NUM MSG %d\n", num_msg);
//     const struct pam_message *message;

//     for(int i = 0; i < num_msg; i++) {
//         message = msg[i];
//         printf("MESSAGE %d: [%d]%s \n", i, message->msg_style, message->msg);
//     }
//     return PAM_SUCCESS;
// }

int
converse(int n, const struct pam_message **msg,
	struct pam_response **resp, void *data)
{
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

int main() {
    int err = PyImport_AppendInittab("pam", PyInit_pam);
    Py_Initialize();
    PyObject * module = PyImport_ImportModule("pam");
    // pam_module_init("quacker");

    const char * value = "test";

    printf("pam_start\n");
    pamc.conv = converse;
    pam_start("su", "tomas", &pamc, &pamh);
    // printf("setting item\n");
    // pam_set_item(pamh, PAM_USER, value);
    // const char * item;
    // printf("reading item\n");
    // pam_get_item(pamh, PAM_USER, (const void **)&item);
    // printf("printing item\n");
    // printf("ITEM: %s\n", item);


    struct pam_xauth_data xauth = {
        3, "ken", 9, "some_data"
    };

    printf("setting xauth\n");
    pam_set_item(pamh, PAM_XAUTHDATA, &xauth);

    struct pam_xauth_data *new_xauth;

    printf("reading xauth\n");
    pam_get_item(pamh, PAM_XAUTHDATA, (const void **)&new_xauth);

    printf("xauth: %d %d\n", new_xauth->namelen, new_xauth->datalen);



    process_handle(pamh);


    // pam_handle_t *pamh = NULL;
    // process_handle(pamh);
    Py_Finalize();
}
