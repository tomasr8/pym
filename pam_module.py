from .pam import Response, PamException, PamHandle

def pam_sm_authenticate(pamh: PamHandle, flags, argv):
    # pamh.logger
    # pamh.XAuthData
    return pamh.PAM_SUCCESS
