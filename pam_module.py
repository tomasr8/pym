from pam_python import PamException, PamHandle, Response, XAuthData


def pam_sm_authenticate(pamh: PamHandle, flags, argv):
    print(pamh.prop)
    # print(flags, argv)
    # print("[CH] handling request..")
    # print("[CH] first sleeping for a bit")
    # import time
    # time.sleep(1)
    # item = pamh.user
    # print("[CH] Got user:", item)
    # pamh.xauthdata = XAuthData("X-data-name", bytes([10, 20, 30, 40]))
    # item = pamh.xauthdata
    # print("[CH] Got XAuthData:", item)

    # pamh.fail_delay(23)
    # print("[CH] set faildelay")

    # print("[CH] Starting covnerastion..")
    # resp = pamh.prompt("Who are you?")
    # print("[CH] Resp:", resp)

    return pamh.PAM_SUCCESS
