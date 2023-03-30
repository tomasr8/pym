from pam_python import PamException, PamHandle, Response


def pam_sm_authenticate(pamh: PamHandle, flags, argv):
    # pamh.logger
    # pamh.XAuthData
    return pamh.PAM_SUCCESS
