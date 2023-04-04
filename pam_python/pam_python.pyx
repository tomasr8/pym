#cython: language_level=3

import importlib
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from syslog import LOG_DEBUG, LOG_ERR
from typing import List, Union

from pam_python import io

cdef extern from "<security/pam_appl.h>":
    pass

cdef extern from "<security/pam_modules.h>":
    # Return values
    cdef int PAM_SUCCESS
    cdef int PAM_OPEN_ERR
    cdef int PAM_SYMBOL_ERR
    cdef int PAM_SERVICE_ERR
    cdef int PAM_SYSTEM_ERR
    cdef int PAM_BUF_ERR
    cdef int PAM_PERM_DENIED
    cdef int PAM_AUTH_ERR
    cdef int PAM_CRED_INSUFFICIENT
    cdef int PAM_AUTHINFO_UNAVAIL
    cdef int PAM_USER_UNKNOWN
    cdef int PAM_MAXTRIES
    cdef int PAM_NEW_AUTHTOK_REQD
    cdef int PAM_ACCT_EXPIRED
    cdef int PAM_SESSION_ERR
    cdef int PAM_CRED_UNAVAIL
    cdef int PAM_CRED_EXPIRED
    cdef int PAM_CRED_ERR
    cdef int PAM_NO_MODULE_DATA
    cdef int PAM_CONV_ERR
    cdef int PAM_AUTHTOK_ERR
    cdef int PAM_AUTHTOK_RECOVERY_ERR
    cdef int PAM_AUTHTOK_LOCK_BUSY
    cdef int PAM_AUTHTOK_DISABLE_AGING
    cdef int PAM_TRY_AGAIN
    cdef int PAM_IGNORE
    cdef int PAM_ABORT
    cdef int PAM_AUTHTOK_EXPIRED
    cdef int PAM_MODULE_UNKNOWN
    cdef int PAM_BAD_ITEM
    cdef int PAM_CONV_AGAIN
    cdef int PAM_INCOMPLETE
    # Flags
    cdef int PAM_SILENT
    cdef int PAM_DISALLOW_NULL_AUTHTOK
    cdef int PAM_ESTABLISH_CRED
    cdef int PAM_DELETE_CRED
    cdef int PAM_REINITIALIZE_CRED
    cdef int PAM_REFRESH_CRED
    cdef int PAM_CHANGE_EXPIRED_AUTHTOK
    # Internal flags
    cdef int PAM_PRELIM_CHECK
    cdef int PAM_UPDATE_AUTHTOK
    # Item types
    cdef int PAM_SERVICE   
    cdef int PAM_USER
    cdef int PAM_TTY  
    cdef int PAM_RHOST
    cdef int PAM_CONV
    cdef int PAM_AUTHTOK
    cdef int PAM_OLDAUTHTOK
    cdef int PAM_RUSER
    cdef int PAM_USER_PROMPT
    # Linux-PAM item type extensions
    cdef int PAM_FAIL_DELAY
    cdef int PAM_XDISPLAY
    cdef int PAM_XAUTHDATA
    cdef int PAM_AUTHTOK_TYPE
    # Message styles (pam_message)
    cdef int PAM_PROMPT_ECHO_OFF
    cdef int PAM_PROMPT_ECHO_ON
    cdef int PAM_ERROR_MSG
    cdef int PAM_TEXT_INFO 
    # Linux-PAM message style extensions
    cdef int PAM_RADIO_TYPE
    cdef int PAM_BINARY_PROMPT
    # Linux-PAM pam_set_data cleanup error_status
    cdef int PAM_DATA_REPLACE
    cdef int PAM_DATA_SILENT


cdef extern from "pam.h":
    cdef int PAM_PYTHON_GET_ITEM
    cdef int PAM_PYTHON_SET_ITEM
    cdef int PAM_PYTHON_FAIL_DELAY
    cdef int PAM_PYTHON_GET_USER
    cdef int PAM_PYTHON_CONVERSE
    cdef int PAM_PYTHON_STERROR
    cdef int PAM_PYTHON_SYSLOG


# Based on pam_deny.so
# https://github.com/linux-pam/linux-pam/blob/master/modules/pam_deny/pam_deny.c
default_errors = {
    "pam_sm_authenticate": PAM_AUTH_ERR,
    "pam_sm_setcred": PAM_CRED_ERR,
    "pam_sm_acct_mgmt": PAM_AUTH_ERR,
    "pam_sm_open_session": PAM_SESSION_ERR,
    "pam_sm_close_session": PAM_SESSION_ERR,
    "pam_sm_chauthtok": PAM_AUTHTOK_ERR
}


class PamException(Exception):
    """Base PAM exception

    This exception is raised for any unsuccessful pam_* call
    (i.e. the return value is not PAM_SUCCESS).

    Example:
        try:
            pamh.get_user()
        except PamException as e:
            print(e)
    """

    def __init__(self, err_num, description, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.err_num = err_num
        self.description = description

    def __str__(self):
        return f"PamException<{self.err_num}, {self.description}>"


@dataclass
class XAuthData:
    """Python equivalent for the 'pam_xauth_data' struct from _pam_types.h"""

    name: str
    data: bytes


@dataclass
class Message:
    """Python equivalent for the 'pam_message' struct from _pam_types.h"""

    msg_style: int
    msg: str


@dataclass
class Response:
    """Python equivalent for the 'pam_response' struct from _pam_types.h"""

    resp: str
    resp_retcode: int


def exit_on_io_error(f):
    def _check_errors(self: PamHandle, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except (EOFError, IOError):
            sys.exit(default_errors[self.pam_fn_name])

    return _check_errors


class IPCWrapper:
    def __init__(self, read_fd, write_fd):
        self.read_end = os.fdopen(read_fd, "rb")
        self.write_end = os.fdopen(write_fd, "wb", buffering=0) # Write data to the pipe immediately

    @exit_on_io_error
    def read_bytes(self, n):
        return io.read_bytes(self.read_end, n)

    @exit_on_io_error
    def read_int(self):
        return io.read_int(self.read_end)

    @exit_on_io_error
    def read_string(self, n):
        return io.read_string(self.read_end, n)

    @exit_on_io_error
    def write_bytes(self):
        return io.write_bytes(self.write_end)

    @exit_on_io_error
    def write_int(self):
        return io.write_int(self.write_end)

    @exit_on_io_error
    def write_string(self):
        return io.write_string(self.write_end)

class PamHandle:
    """Python wrapper for the PAM handle providing access to its properties

    Do not try to instantiate this in user code, the instance is passed
    as an argument in every pam_sm_* function.
    """

    PamException = PamException
    XAuthData = XAuthData
    Message = Message
    Response = Response

    # Return values
    PAM_SUCCESS                = PAM_SUCCESS
    PAM_OPEN_ERR               = PAM_OPEN_ERR
    PAM_SYMBOL_ERR             = PAM_SYMBOL_ERR
    PAM_SERVICE_ERR            = PAM_SERVICE_ERR
    PAM_SYSTEM_ERR             = PAM_SYSTEM_ERR
    PAM_BUF_ERR                = PAM_BUF_ERR
    PAM_PERM_DENIED            = PAM_PERM_DENIED
    PAM_AUTH_ERR               = PAM_AUTH_ERR
    PAM_CRED_INSUFFICIENT      = PAM_CRED_INSUFFICIENT
    PAM_AUTHINFO_UNAVAIL       = PAM_AUTHINFO_UNAVAIL
    PAM_USER_UNKNOWN           = PAM_USER_UNKNOWN
    PAM_MAXTRIES               = PAM_MAXTRIES
    PAM_NEW_AUTHTOK_REQD       = PAM_NEW_AUTHTOK_REQD
    PAM_ACCT_EXPIRED           = PAM_ACCT_EXPIRED
    PAM_SESSION_ERR            = PAM_SESSION_ERR
    PAM_CRED_UNAVAIL           = PAM_CRED_UNAVAIL
    PAM_CRED_EXPIRED           = PAM_CRED_EXPIRED
    PAM_CRED_ERR               = PAM_CRED_ERR
    PAM_NO_MODULE_DATA         = PAM_NO_MODULE_DATA
    PAM_CONV_ERR               = PAM_CONV_ERR
    PAM_AUTHTOK_ERR            = PAM_AUTHTOK_ERR
    PAM_AUTHTOK_RECOVERY_ERR   = PAM_AUTHTOK_RECOVERY_ERR
    PAM_AUTHTOK_LOCK_BUSY      = PAM_AUTHTOK_LOCK_BUSY
    PAM_AUTHTOK_DISABLE_AGING  = PAM_AUTHTOK_DISABLE_AGING
    PAM_TRY_AGAIN              = PAM_TRY_AGAIN
    PAM_IGNORE                 = PAM_IGNORE
    PAM_ABORT                  = PAM_ABORT
    PAM_AUTHTOK_EXPIRED        = PAM_AUTHTOK_EXPIRED
    PAM_MODULE_UNKNOWN         = PAM_MODULE_UNKNOWN
    PAM_BAD_ITEM               = PAM_BAD_ITEM
    PAM_CONV_AGAIN             = PAM_CONV_AGAIN
    PAM_INCOMPLETE             = PAM_INCOMPLETE
    # Flags
    PAM_SILENT                 = PAM_SILENT
    PAM_DISALLOW_NULL_AUTHTOK  = PAM_DISALLOW_NULL_AUTHTOK
    PAM_ESTABLISH_CRED         = PAM_ESTABLISH_CRED
    PAM_DELETE_CRED            = PAM_DELETE_CRED
    PAM_REINITIALIZE_CRED      = PAM_REINITIALIZE_CRED
    PAM_REFRESH_CRED           = PAM_REFRESH_CRED
    PAM_CHANGE_EXPIRED_AUTHTOK = PAM_CHANGE_EXPIRED_AUTHTOK
    # Internal flags
    PAM_PRELIM_CHECK           = PAM_PRELIM_CHECK
    PAM_UPDATE_AUTHTOK         = PAM_UPDATE_AUTHTOK
    # Item types
    PAM_SERVICE                = PAM_SERVICE
    PAM_USER                   = PAM_USER
    PAM_TTY                    = PAM_TTY
    PAM_RHOST                  = PAM_RHOST
    PAM_CONV                   = PAM_CONV
    PAM_AUTHTOK                = PAM_AUTHTOK
    PAM_OLDAUTHTOK             = PAM_OLDAUTHTOK
    PAM_RUSER                  = PAM_RUSER
    PAM_USER_PROMPT            = PAM_USER_PROMPT
    # Linux-PAM item type extensions
    PAM_FAIL_DELAY             = PAM_FAIL_DELAY
    PAM_XDISPLAY               = PAM_XDISPLAY
    PAM_XAUTHDATA              = PAM_XAUTHDATA
    PAM_AUTHTOK_TYPE           = PAM_AUTHTOK_TYPE
    # Message styles (pam_message)
    PAM_PROMPT_ECHO_OFF        = PAM_PROMPT_ECHO_OFF
    PAM_PROMPT_ECHO_ON         = PAM_PROMPT_ECHO_ON
    PAM_ERROR_MSG              = PAM_ERROR_MSG
    PAM_TEXT_INFO              = PAM_TEXT_INFO
    # Linux-PAM message style extensions
    PAM_RADIO_TYPE             = PAM_RADIO_TYPE
    PAM_BINARY_PROMPT          = PAM_BINARY_PROMPT
    # Linux-PAM pam_set_data cleanup error_status
    PAM_DATA_REPLACE           = PAM_DATA_REPLACE
    PAM_DATA_SILENT            = PAM_DATA_SILENT

    def __init__(self, read_fd, write_fd, pam_fn_name):
        self._ipc = IPCWrapper(read_fd, write_fd)
        self.pam_fn_name = pam_fn_name

    @property
    def service(self):
        return self._get_item(PAM_SERVICE)

    @service.setter
    def service(self, value):
        self._set_item(PAM_SERVICE, value)

    @property
    def user(self):
        return self._get_item(PAM_USER)

    @user.setter
    def user(self, value):
        self._set_item(PAM_USER, value)

    @property
    def xauthdata(self):
        return self._get_item(PAM_XAUTHDATA)

    @xauthdata.setter
    def xauthdata(self, value: XAuthData):
        self._set_item(PAM_XAUTHDATA, value)

    def get_user(self, prompt=None):
        """Wrapper for pam_get_user()"""
        self._ipc.write_int(PAM_PYTHON_GET_USER)

        if prompt is None:
            self._ipc.write_int(0)
        else:
            assert isinstance(prompt, str)
            self._ipc.write_int(len(prompt))
            self._ipc.write_string(prompt)

        retval = self._ipc.read_int()
        if retval != PAM_SUCCESS:
            self.logger.log(f"Failed to get user [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

        length = self._ipc.read_int()
        return self._ipc.read_string(length)

    def fail_delay(self, usec: int):
        """Set the fail delay"""
        self._ipc.write_int(PAM_PYTHON_FAIL_DELAY)
        self._ipc.write_int(usec)

        retval = self._ipc.read_int()
        if retval != PAM_SUCCESS:
            self.logger.log(f"Failed to set fail delay [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

    def converse(self, msgs: Union[List[Message], Message]):
        """Interface for the application conversation function"""
        if not isinstance(msgs, list):
            msgs = [msgs]

        self._ipc.write_int(PAM_PYTHON_CONVERSE)
        self._ipc.write_int(len(msgs))

        for msg in msgs:
            self._ipc.write_int(msg.msg_style)
            self._ipc.write_int(len(msg.msg))
            self._ipc.write_string(msg.msg)

        retval = self._ipc.read_int()
        if retval != PAM_SUCCESS:
            self.logger.log(f"Error when getting PAM_CONV [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

        responses = []
        for _ in range(len(msgs)):
            resp_retcode = self._ipc.read_int()
            resp_len = self._ipc.read_int()
            if resp_len == 0:
                responses.append(Response(None, resp_retcode))
            else:
                data = self._ipc.read_string(resp_len)
                responses.append(Response(data, resp_retcode))

        return responses

    def prompt(self, msg, msg_style=PAM_PROMPT_ECHO_OFF):
        """Simplified conversation interface with a single message"""
        if isinstance(msg, Message):
            return self.converse(msg)
        else:
            assert isinstance(msg, str)
            return self.converse(Message(msg_style=msg_style, msg=msg))

    def strerror(self, err_num):
        """Get a description from an error number"""
        self._ipc.write_int(PAM_PYTHON_STERROR)
        self._ipc.write_int(err_num)
        length = self._ipc.read_int()
        return self._ipc.read_string(length)

    def log(self, msg, priority=LOG_ERR):
        """Wrapper for pam_syslog()"""
        print(msg)
        assert isinstance(msg, str)
        self._ipc.write_int(PAM_PYTHON_SYSLOG)
        self._ipc.write_int(priority)
        self._ipc.write_int(len(msg))
        self._ipc.write_string(msg)

    def debug(self, msg: str):
        """log with a debug priority"""
        self.log(msg, LOG_DEBUG)

    def _get_item(self, item_type):
        if item_type == PAM_CONV or item_type == PAM_FAIL_DELAY:
            # We don't allow accessing these items
            return None
        elif item_type == PAM_XAUTHDATA:
            self._ipc.write_int(PAM_PYTHON_GET_ITEM)
            self._ipc.write_int(item_type)
            retval = self._ipc.read_int()

            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when getting XAuthData [retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))

            namelen = self._ipc.read_int()
            # print(f"[CH] namelen {namelen}")
            name = self._ipc.read_string(namelen)
            datalen = self._ipc.read_int()
            # print(f"[CH] datalen {datalen}")
            data = self._ipc.read_bytes(datalen)
            return XAuthData(name, data)
        else:
            self._ipc.write_int(PAM_PYTHON_GET_ITEM)
            self._ipc.write_int(item_type)
            retval = self._ipc.read_int()

            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when getting item [item_type={item_type}, retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))

            length = self._ipc.read_int()
            return self._ipc.read_string(length)

    def _set_item(self, item_type, item):
        if item_type == PAM_CONV or item_type == PAM_FAIL_DELAY:
            # We don't allow setting these items
            # Use fail_delay() or converse() instead
            pass
        elif item_type == PAM_XAUTHDATA:
            assert isinstance(item, XAuthData)
            self._ipc.write_int(PAM_PYTHON_SET_ITEM)
            self._ipc.write_int(item_type)
            self._ipc.write_int(len(item.name))
            self._ipc.write_string(item.name)
            self._ipc.write_int(len(item.data))
            self._ipc.write_bytes(item.data)
            retval = self._ipc.read_int()

            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when setting XAuthData [retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))
        else:
            assert isinstance(item, str)
            self._ipc.write_int(PAM_PYTHON_SET_ITEM)
            self._ipc.write_int(item_type)
            self._ipc.write_int(len(item))
            self._ipc.write_string(item)
            retval = self._ipc.read_int()

            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when setting item [item_type={item_type}, retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))


def _load_module(file_path):
    module_name = Path(file_path).stem
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


cdef public int python_handle_request(int read_end, int write_end, int flags, int argc, const char ** argv, char *pam_fn_name):
    fn_name = pam_fn_name.decode("utf-8")
    pam_handle = PamHandle(read_end, write_end, pam_fn_name)

    if argc == 0:
        pam_handle.log("No python module provided")
        return default_errors[fn_name]

    args = []
    for i in range(argc):
        args.append(argv[i].decode("utf-8"))

    pam_handle.debug(f"Importing {args[0]}")
    try:
        module = _load_module(args[0])
    except Exception as e:
        pam_handle.log(f"Failed to import python module: {e}")
        return default_errors[fn_name]

    handler = getattr(module, fn_name, None)
    if handler is None:
        pam_handle.log(f"No python handler provided for {fn_name}")
        return default_errors[fn_name]

    try:
        retval = handler(pam_handle, flags, args[1:])
    except Exception as e:
        pam_handle.log(f"Exception ocurred while running python handler: [flags={flags}, args={args[1:]}, fn_name={fn_name}]" +
                       f"   Exception: {e}")
        return default_errors[fn_name]

    if not isinstance(retval, int):
        pam_handle.log(f"Return value must be an integer, received {type(retval)} [value={retval}]")
        return default_errors[fn_name]
    else:
        return retval
