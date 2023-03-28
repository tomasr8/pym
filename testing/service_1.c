#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

void cleanup(pam_handle_t *pamh, void *data, int error_status) {
    printf("Cleaning up..\n");
}

void register_cleanup(pam_handle_t *pamh) {
    pam_set_data(pamh, "service-test-1", NULL, cleanup);
}

int x = 0;

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    register_cleanup(pamh);
    printf("Inside PAM module!\n");
    x++;
    printf("X = %d\n", x);
    char * user;
    pam_get_item(pamh, PAM_USER, (const void **)&user);
    printf("User is %s\n", user);
    printf("Sleeping for a bit..\n");
    int t = rand() % 5;
    sleep(t);
    printf("Returning from PAM module!\n");
    return PAM_SUCCESS;
}
