import syslog
from dataclasses import dataclass
from typing import List, Union


class PamException(Exception):
    def __init__(self, err_num: int, description: str, *args, **kwargs) -> None: ...

@dataclass
class XAuthData:
    name: str
    data: bytes

@dataclass
class Message:
    msg_style: int
    msg: str

@dataclass
class Response:
    resp: str
    resp_retcode: int

class PamHandle:
    PamException: type[PamException]
    XAuthData: type[XAuthData]
    Message: type[Message]
    Response: type[Response]

    # Return values
    PAM_SUCCESS                : int
    PAM_OPEN_ERR               : int
    PAM_SYMBOL_ERR             : int
    PAM_SERVICE_ERRE           : int
    PAM_SYSTEM_ERR             : int
    PAM_BUF_ERR                : int
    PAM_PERM_DENIED            : int
    PAM_AUTH_ERR               : int
    PAM_CRED_INSUFFICIENT      : int
    PAM_AUTHINFO_UNAVAIL       : int
    PAM_USER_UNKNOWN           : int
    PAM_MAXTRIES               : int
    PAM_NEW_AUTHTOK_REQD       : int
    PAM_ACCT_EXPIRED           : int
    PAM_SESSION_ERR            : int
    PAM_CRED_UNAVAIL           : int
    PAM_CRED_EXPIRED           : int
    PAM_CRED_ERR               : int
    PAM_NO_MODULE_DATA         : int
    PAM_CONV_ERR               : int
    PAM_AUTHTOK_ERR            : int
    PAM_AUTHTOK_RECOVERY_ERR   : int
    PAM_AUTHTOK_LOCK_BUSY      : int
    PAM_AUTHTOK_DISABLE_AGING  : int
    PAM_TRY_AGAIN              : int
    PAM_IGNORE                 : int
    PAM_ABORT                  : int
    PAM_AUTHTOK_EXPIRED        : int
    PAM_MODULE_UNKNOWN         : int
    PAM_BAD_ITEM               : int
    PAM_CONV_AGAIN             : int
    PAM_INCOMPLETE             : int
    # Flags
    PAM_SILENT                 : int
    PAM_DISALLOW_NULL_AUTHTOK  : int
    PAM_ESTABLISH_CRED         : int
    PAM_DELETE_CRED            : int
    PAM_REINITIALIZE_CRED      : int
    PAM_REFRESH_CRED           : int
    PAM_CHANGE_EXPIRED_AUTHTOK : int
    # Internal flags
    PAM_PRELIM_CHECK           : int
    PAM_UPDATE_AUTHTOK         : int
    # Item types
    PAM_SERVICE                : int
    PAM_USER                   : int
    PAM_TTY                    : int
    PAM_RHOST                  : int
    PAM_CONV                   : int
    PAM_AUTHTOK                : int
    PAM_OLDAUTHTOK             : int
    PAM_RUSER                  : int
    PAM_USER_PROMPT            : int
    # Linux-PAM item type extensions
    PAM_FAIL_DELAY             : int
    PAM_XDISPLAY               : int
    PAM_XAUTHDATA              : int
    PAM_AUTHTOK_TYPE           : int
    # Message styles (pam_message)
    PAM_PROMPT_ECHO_OFF        : int
    PAM_PROMPT_ECHO_ON         : int
    PAM_ERROR_MSG              : int
    PAM_TEXT_INFO              : int
    # Linux-Pam message style extensions
    PAM_RADIO_TYPE             : int
    PAM_BINARY_PROMPT          : int
    # Linux-PAM pam_set_data cleanup error_status
    PAM_DATA_REPLACE           : int
    PAM_DATA_SILENT            : int

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

    def get_user(self, prompt: Union[str, None] = None) -> str: ...
    def fail_delay(self, usec: int) -> None: ...
    def converse(self, msgs: Union[List[Message], Message]) -> List[Response]: ...
    def prompt(self, msg: str, msg_style: int = PAM_PROMPT_ECHO_OFF) -> List[Response]: ...
    def strerror(self, err_num: int) -> str: ...
    def log(self, msg, priority=syslog.LOG_ERR) -> None: ...
    def debug(self, msg: str) -> None: ...
