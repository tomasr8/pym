from typing import overload, Union, List
from dataclasses import dataclass


class PamException(Exception):
    def __init__(self, err_num: int, description: str, *args, **kwargs) -> PamException: ...
    def __str__(self) -> str: ...

@dataclass
class XAuthData:
    name: str
    data: str

@dataclass
class Message:
    msg_style: int
    msg: str

@dataclass
class Response:
    resp: str
    resp_retcode: int

class PamHandle:
    PamException: PamException
    XAuthData: XAuthData
    Message: Message
    Response: Response

        # authentication results
    PAM_AUTH_ERR          : int
    PAM_CRED_INSUFFICIENT : int
    PAM_AUTHINFO_UNAVAIL  : int
    PAM_USER_UNKNOWN      : int
    PAM_MAXTRIES          : int
    # pam_[gs]et_item results
    PAM_BAD_ITEM          : int
    PAM_BUF_ERR           : int
    PAM_SUCCESS           : int
    PAM_PERM_DENIED       : int
    PAM_SYSTEM_ERR        : int
    # pam_[gs]et_item item_type
    PAM_SERVICE           : int
    PAM_USER              : int
    PAM_USER_PROMPT       : int
    PAM_TTY               : int
    PAM_RUSER             : int
    PAM_RHOST             : int
    PAM_AUTHTOK           : int
    PAM_OLDAUTHTOK        : int
    PAM_CONV              : int
    # non-portable item_types
    PAM_FAIL_DELAY        : int
    PAM_XDISPLAY          : int
    PAM_XAUTHDATA         : int
    PAM_AUTHTOK_TYPE      : int
    # pam_message msg_style
    PAM_PROMPT_ECHO_OFF   : int
    PAM_PROMPT_ECHO_ON    : int
    PAM_ERROR_MSG         : int
    PAM_TEXT_INFO         : int 

    @property
    def service(self) -> str: ...

    @service.setter
    def service(self, value: str) -> None: ...

    @property
    def user(self) -> str: ...

    @user.setter
    def user(self, value: str) -> None: ...

    @property
    def xauthdata(self) -> XAuthData: ...

    @xauthdata.setter
    def xauthdata(self, value: XAuthData) -> None: ...

    def get_user(self, prompt: str =None) -> str: ...

    def fail_delay(self, usec: int) -> None: ...

    def conversation(self, msgs: Union[List[Message], Message]) -> List[Response]: ...

    def strerror(self, err_num: int) -> str: ...
