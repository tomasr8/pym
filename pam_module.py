from .pam import Response, PamException, PamHandle

def pam_sm_authenticate(pamh: PamHandle, flags, argv):
    return pamh.PAM_SUCCESS
