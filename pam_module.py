from pam import Response, PamException, PamHandle

h = PamHandle()

def pam_sm_authenticate(pamh: PamHandle):
    ...
