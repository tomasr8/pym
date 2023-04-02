#cython: language_level=3

import importlib
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from syslog import LOG_DEBUG, LOG_ERR
from typing import List, Union


cdef extern from "<security/pam_appl.h>":
    pass

cdef extern from "<security/pam_modules.h>":
    # Return values
    cdef int _PAM_SUCCESS "PAM_SUCCESS"
    cdef int _PAM_OPEN_ERR "PAM_OPEN_ERR"
    cdef int _PAM_SYMBOL_ERR "PAM_SYMBOL_ERR"
    cdef int _PAM_SERVICE_ERR "PAM_SERVICE_ERR"
    cdef int _PAM_SYSTEM_ERR "PAM_SYSTEM_ERR"
    cdef int _PAM_BUF_ERR "PAM_BUF_ERR"
    cdef int _PAM_PERM_DENIED "PAM_PERM_DENIED"
    cdef int _PAM_AUTH_ERR "PAM_AUTH_ERR"
    cdef int _PAM_CRED_INSUFFICIENT "PAM_CRED_INSUFFICIENT"
    cdef int _PAM_AUTHINFO_UNAVAIL "PAM_AUTHINFO_UNAVAIL"
    cdef int _PAM_USER_UNKNOWN "PAM_USER_UNKNOWN"
    cdef int _PAM_MAXTRIES "PAM_MAXTRIES"
    cdef int _PAM_NEW_AUTHTOK_REQD "PAM_NEW_AUTHTOK_REQD"
    cdef int _PAM_ACCT_EXPIRED "PAM_ACCT_EXPIRED"
    cdef int _PAM_SESSION_ERR "PAM_SESSION_ERR"
    cdef int _PAM_CRED_UNAVAIL "PAM_CRED_UNAVAIL"
    cdef int _PAM_CRED_EXPIRED "PAM_CRED_EXPIRED"
    cdef int _PAM_CRED_ERR "PAM_CRED_ERR"
    cdef int _PAM_NO_MODULE_DATA "PAM_NO_MODULE_DATA"
    cdef int _PAM_CONV_ERR "PAM_CONV_ERR"
    cdef int _PAM_AUTHTOK_ERR "PAM_AUTHTOK_ERR"
    cdef int _PAM_AUTHTOK_RECOVERY_ERR "PAM_AUTHTOK_RECOVERY_ERR"
    cdef int _PAM_AUTHTOK_LOCK_BUSY "PAM_AUTHTOK_LOCK_BUSY"
    cdef int _PAM_AUTHTOK_DISABLE_AGING "PAM_AUTHTOK_DISABLE_AGING"
    cdef int _PAM_TRY_AGAIN "PAM_TRY_AGAIN"
    cdef int _PAM_IGNORE "PAM_IGNORE"
    cdef int _PAM_ABORT "PAM_ABORT"
    cdef int _PAM_AUTHTOK_EXPIRED "PAM_AUTHTOK_EXPIRED"
    cdef int _PAM_MODULE_UNKNOWN "PAM_MODULE_UNKNOWN"
    cdef int _PAM_BAD_ITEM "PAM_BAD_ITEM"
    cdef int _PAM_CONV_AGAIN "PAM_CONV_AGAIN"
    cdef int _PAM_INCOMPLETE "PAM_INCOMPLETE"
    # Flags
    cdef int _PAM_SILENT "PAM_SILENT"
    cdef int _PAM_DISALLOW_NULL_AUTHTOK "PAM_DISALLOW_NULL_AUTHTOK"
    cdef int _PAM_ESTABLISH_CRED "PAM_ESTABLISH_CRED"
    cdef int _PAM_DELETE_CRED "PAM_DELETE_CRED"
    cdef int _PAM_REINITIALIZE_CRED "PAM_REINITIALIZE_CRED"
    cdef int _PAM_REFRESH_CRED "PAM_REFRESH_CRED"
    cdef int _PAM_CHANGE_EXPIRED_AUTHTOK "PAM_CHANGE_EXPIRED_AUTHTOK"
    # Internal flags
    cdef int _PAM_PRELIM_CHECK "PAM_PRELIM_CHECK"
    cdef int _PAM_UPDATE_AUTHTOK "PAM_UPDATE_AUTHTOK"
    # Item types
    cdef int _PAM_SERVICE    "PAM_SERVICE   "
    cdef int _PAM_USER "PAM_USER"
    cdef int _PAM_TTY   "PAM_TTY  "
    cdef int _PAM_RHOST "PAM_RHOST"
    cdef int _PAM_CONV "PAM_CONV"
    cdef int _PAM_AUTHTOK "PAM_AUTHTOK"
    cdef int _PAM_OLDAUTHTOK "PAM_OLDAUTHTOK"
    cdef int _PAM_RUSER "PAM_RUSER"
    cdef int _PAM_USER_PROMPT "PAM_USER_PROMPT"
    # Linux-PAM item type extensions
    cdef int _PAM_FAIL_DELAY "PAM_FAIL_DELAY"
    cdef int _PAM_XDISPLAY "PAM_XDISPLAY"
    cdef int _PAM_XAUTHDATA "PAM_XAUTHDATA"
    cdef int _PAM_AUTHTOK_TYPE "PAM_AUTHTOK_TYPE"
    # Message styles (pam_message)
    cdef int _PAM_PROMPT_ECHO_OFF "PAM_PROMPT_ECHO_OFF"
    cdef int _PAM_PROMPT_ECHO_ON "PAM_PROMPT_ECHO_ON"
    cdef int _PAM_ERROR_MSG "PAM_ERROR_MSG"
    cdef int _PAM_TEXT_INFO  "PAM_TEXT_INFO "
    # Linux-Pam message style extensions
    cdef int _PAM_RADIO_TYPE "PAM_RADIO_TYPE"
    cdef int _PAM_BINARY_PROMPT "PAM_BINARY_PROMPT"
    # Linux-PAM pam_set_data cleanup error_status
    cdef int _PAM_DATA_REPLACE "PAM_DATA_REPLACE"
    cdef int _PAM_DATA_SILENT "PAM_DATA_SILENT"


cdef extern from "pipe.h":
    cdef int _PAM_METHOD_GET_ITEM
    cdef int _PAM_METHOD_SET_ITEM
    cdef int _PAM_METHOD_FAIL_DELAY
    cdef int _PAM_METHOD_GET_USER
    cdef int _PAM_METHOD_CONVERSE
    cdef int _PAM_METHOD_STERROR
    cdef int _PAM_METHOD_SYSLOG


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


def read_bytes(f, n):
    total_read = 0
    data = bytearray()
    while total_read < n:
        remaining = n - total_read
        _data = f.read(remaining)
        _data_len = len(_data)
        if _data_len == 0:
            raise EOFError
        total_read += _data_len
        data.extend(_data)
    return bytes(data)

def read_string(f, n):
    return read_bytes(f, n).decode("utf-8")

def read_int(f):
    return int.from_bytes(read_bytes(f, 4), sys.byteorder)

def write_bytes(f, data):
    f.write(data)

def write_string(f, string):
    write_bytes(f, string.encode("utf-8"))

def write_int(f, num):
    write_bytes(f, num.to_bytes(4, sys.byteorder))

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
    PAM_SUCCESS                = _PAM_SUCCESS
    PAM_OPEN_ERR               = _PAM_OPEN_ERR
    PAM_SYMBOL_ERR             = _PAM_SYMBOL_ERR
    PAM_SERVICE_ERR            = _PAM_SERVICE_ERR
    PAM_SYSTEM_ERR             = _PAM_SYSTEM_ERR
    PAM_BUF_ERR                = _PAM_BUF_ERR
    PAM_PERM_DENIED            = _PAM_PERM_DENIED
    PAM_AUTH_ERR               = _PAM_AUTH_ERR
    PAM_CRED_INSUFFICIENT      = _PAM_CRED_INSUFFICIENT
    PAM_AUTHINFO_UNAVAIL       = _PAM_AUTHINFO_UNAVAIL
    PAM_USER_UNKNOWN           = _PAM_USER_UNKNOWN
    PAM_MAXTRIES               = _PAM_MAXTRIES
    PAM_NEW_AUTHTOK_REQD       = _PAM_NEW_AUTHTOK_REQD
    PAM_ACCT_EXPIRED           = _PAM_ACCT_EXPIRED
    PAM_SESSION_ERR            = _PAM_SESSION_ERR
    PAM_CRED_UNAVAIL           = _PAM_CRED_UNAVAIL
    PAM_CRED_EXPIRED           = _PAM_CRED_EXPIRED
    PAM_CRED_ERR               = _PAM_CRED_ERR
    PAM_NO_MODULE_DATA         = _PAM_NO_MODULE_DATA
    PAM_CONV_ERR               = _PAM_CONV_ERR
    PAM_AUTHTOK_ERR            = _PAM_AUTHTOK_ERR
    PAM_AUTHTOK_RECOVERY_ERR   = _PAM_AUTHTOK_RECOVERY_ERR
    PAM_AUTHTOK_LOCK_BUSY      = _PAM_AUTHTOK_LOCK_BUSY
    PAM_AUTHTOK_DISABLE_AGING  = _PAM_AUTHTOK_DISABLE_AGING
    PAM_TRY_AGAIN              = _PAM_TRY_AGAIN
    PAM_IGNORE                 = _PAM_IGNORE
    PAM_ABORT                  = _PAM_ABORT
    PAM_AUTHTOK_EXPIRED        = _PAM_AUTHTOK_EXPIRED
    PAM_MODULE_UNKNOWN         = _PAM_MODULE_UNKNOWN
    PAM_BAD_ITEM               = _PAM_BAD_ITEM
    PAM_CONV_AGAIN             = _PAM_CONV_AGAIN
    PAM_INCOMPLETE             = _PAM_INCOMPLETE
    # Flags
    PAM_SILENT                 = _PAM_SILENT
    PAM_DISALLOW_NULL_AUTHTOK  = _PAM_DISALLOW_NULL_AUTHTOK
    PAM_ESTABLISH_CRED         = _PAM_ESTABLISH_CRED
    PAM_DELETE_CRED            = _PAM_DELETE_CRED
    PAM_REINITIALIZE_CRED      = _PAM_REINITIALIZE_CRED
    PAM_REFRESH_CRED           = _PAM_REFRESH_CRED
    PAM_CHANGE_EXPIRED_AUTHTOK = _PAM_CHANGE_EXPIRED_AUTHTOK
    # Internal flags
    PAM_PRELIM_CHECK           = _PAM_PRELIM_CHECK
    PAM_UPDATE_AUTHTOK         = _PAM_UPDATE_AUTHTOK
    # Item types
    PAM_SERVICE                = _PAM_SERVICE
    PAM_USER                   = _PAM_USER
    PAM_TTY                    = _PAM_TTY
    PAM_RHOST                  = _PAM_RHOST
    PAM_CONV                   = _PAM_CONV
    PAM_AUTHTOK                = _PAM_AUTHTOK
    PAM_OLDAUTHTOK             = _PAM_OLDAUTHTOK
    PAM_RUSER                  = _PAM_RUSER
    PAM_USER_PROMPT            = _PAM_USER_PROMPT
    # Linux-PAM item type extensions
    PAM_FAIL_DELAY             = _PAM_FAIL_DELAY
    PAM_XDISPLAY               = _PAM_XDISPLAY
    PAM_XAUTHDATA              = _PAM_XAUTHDATA
    PAM_AUTHTOK_TYPE           = _PAM_AUTHTOK_TYPE
    # Message styles (pam_message)
    PAM_PROMPT_ECHO_OFF        = _PAM_PROMPT_ECHO_OFF
    PAM_PROMPT_ECHO_ON         = _PAM_PROMPT_ECHO_ON
    PAM_ERROR_MSG              = _PAM_ERROR_MSG
    PAM_TEXT_INFO              = _PAM_TEXT_INFO
    # Linux-Pam message style extensions
    PAM_RADIO_TYPE             = _PAM_RADIO_TYPE
    PAM_BINARY_PROMPT          = _PAM_BINARY_PROMPT
    # Linux-PAM pam_set_data cleanup error_status
    PAM_DATA_REPLACE           = _PAM_DATA_REPLACE
    PAM_DATA_SILENT            = _PAM_DATA_SILENT

    locals()['prop'] = 123

    def __init__(self, read_end, write_end):
        self._read_end = os.fdopen(read_end, "rb")
        self._write_end = os.fdopen(write_end, "wb", buffering=0) # Write data to the pipe immediately

    @property
    def service(self):
        return self._get_item(_PAM_SERVICE)

    @service.setter
    def service(self, value):
        self._set_item(_PAM_SERVICE, value)

    @property
    def user(self):
        return self._get_item(_PAM_USER)

    @user.setter
    def user(self, value):
        self._set_item(_PAM_USER, value)

    @property
    def xauthdata(self):
        return self._get_item(_PAM_XAUTHDATA)

    @xauthdata.setter
    def xauthdata(self, value: XAuthData):
        self._set_item(_PAM_XAUTHDATA, value)

    def get_user(self, prompt=None):
        """Wrapper for pam_get_user()"""
        write_int(self._write_end, _PAM_METHOD_GET_USER)

        if prompt is None:
            write_int(self._write_end, 0)
        else:
            assert isinstance(prompt, str)
            write_int(self._write_end, len(prompt))
            write_string(self._write_end, prompt)

        retval = read_int(self._read_end)
        if retval != _PAM_SUCCESS:
            self.logger.log(f"Failed to get user [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

        length = read_int(self._read_end)
        return read_string(self._read_end, length)

    def fail_delay(self, usec: int):
        """Set the fail delay"""
        write_int(self._write_end, _PAM_METHOD_FAIL_DELAY)
        write_int(self._write_end, usec)

        retval = read_int(self._read_end)
        if retval != _PAM_SUCCESS:
            self.logger.log(f"Failed to set fail delay [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

    def converse(self, msgs: Union[List[Message], Message]):
        """Interface for the application conversation function"""
        if not isinstance(msgs, list):
            msgs = [msgs]

        write_int(self._write_end, _PAM_METHOD_CONVERSE)
        write_int(self._write_end, len(msgs))

        for msg in msgs:
            write_int(self._write_end, msg.msg_style)
            write_int(self._write_end, len(msg.msg))
            write_string(self._write_end, msg.msg)

        retval = read_int(self._read_end)
        if retval != _PAM_SUCCESS:
            self.logger.log(f"Error when getting _PAM_CONV [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

        responses = []
        for _ in range(len(msgs)):
            resp_retcode = read_int(self._read_end)
            resp_len = read_int(self._read_end)
            if resp_len == 0:
                responses.append(Response(None, resp_retcode))
            else:
                data = read_string(self._read_end, resp_len)
                responses.append(Response(data, resp_retcode))

        return responses

    def prompt(self, msg, msg_style=_PAM_PROMPT_ECHO_OFF):
        """Simplified conversation interface with a single message"""
        if isinstance(msg, Message):
            return self.converse(msg)
        else:
            assert isinstance(msg, str)
            return self.converse(Message(msg_style=msg_style, msg=msg))

    def strerror(self, err_num):
        """Get a description from an error number"""
        write_int(self._write_end, _PAM_METHOD_STERROR)
        write_int(self._write_end, err_num)
        length = read_int(self._read_end)
        return read_string(self._read_end, length)

    def log(self, msg, priority=LOG_ERR):
        """Wrapper for pam_syslog()"""
        print(msg)
        assert isinstance(msg, str)
        write_int(self._write_end, _PAM_METHOD_SYSLOG)
        write_int(self._write_end, priority)
        write_int(self._write_end, len(msg))
        write_string(self._write_end, msg)

    def debug(self, msg: str):
        """log with a debug priority"""
        self.log(msg, LOG_DEBUG)

    def _get_item(self, item_type):
        if item_type == _PAM_CONV or item_type == _PAM_FAIL_DELAY:
            # We don't allow accessing these items
            return None
        elif item_type == _PAM_XAUTHDATA:
            write_int(self._write_end, _PAM_METHOD_GET_ITEM)
            write_int(self._write_end, item_type)
            retval = read_int(self._read_end)

            if retval != _PAM_SUCCESS:
                self.logger.log(f"Error when getting XAuthData [retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))

            namelen = read_int(self._read_end)
            # print(f"[CH] namelen {namelen}")
            name = read_string(self._read_end, namelen)
            datalen = read_int(self._read_end)
            # print(f"[CH] datalen {datalen}")
            data = read_bytes(self._read_end, datalen)
            return XAuthData(name, data)
        else:
            write_int(self._write_end, _PAM_METHOD_GET_ITEM)
            write_int(self._write_end, item_type)
            retval = read_int(self._read_end)

            if retval != _PAM_SUCCESS:
                self.logger.log(f"Error when getting item [item_type={item_type}, retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))

            length = read_int(self._read_end)
            return read_string(self._read_end, length)

    def _set_item(self, item_type, item):
        if item_type == _PAM_CONV or item_type == _PAM_FAIL_DELAY:
            # We don't allow setting these items
            # Use fail_delay() or converse() instead
            pass
        elif item_type == _PAM_XAUTHDATA:
            assert isinstance(item, XAuthData)
            write_int(self._write_end, _PAM_METHOD_SET_ITEM)
            write_int(self._write_end, item_type)
            write_int(self._write_end, len(item.name))
            write_string(self._write_end, item.name)
            write_int(self._write_end, len(item.data))
            write_bytes(self._write_end, item.data)
            retval = read_int(self._read_end)

            if retval != _PAM_SUCCESS:
                self.logger.log(f"Error when setting XAuthData [retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))
        else:
            assert isinstance(item, str)
            write_int(self._write_end, _PAM_METHOD_SET_ITEM)
            write_int(self._write_end, item_type)
            write_int(self._write_end, len(item))
            write_string(self._write_end, item)
            retval = read_int(self._read_end)

            if retval != _PAM_SUCCESS:
                self.logger.log(f"Error when setting item [item_type={item_type}, retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))


def _load_module(file_path):
    module_name = Path(file_path).stem
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

# Based on pam_deny.so
# https://github.com/linux-pam/linux-pam/blob/master/modules/pam_deny/pam_deny.c
ERRORS = {
    "pam_sm_authenticate": _PAM_AUTH_ERR,
    "pam_sm_setcred": _PAM_CRED_ERR,
    "pam_sm_acct_mgmt": _PAM_AUTH_ERR,
    "pam_sm_open_session": _PAM_SESSION_ERR,
    "pam_sm_close_session": _PAM_SESSION_ERR,
    "pam_sm_chauthtok": _PAM_AUTHTOK_ERR
}


cdef public int python_handle_request(int read_end, int write_end, int flags, int argc, const char ** argv, char *pam_fn_name):
    fn_name = pam_fn_name.decode("utf-8")
    pam_handle = PamHandle(read_end, write_end)

    if argc == 0:
        pam_handle.log("No python module provided")
        return ERRORS[fn_name]

    args = []
    for i in range(argc):
        args.append(argv[i].decode("utf-8"))

    pam_handle.debug(f"Importing {args[0]}")
    try:
        module = _load_module(args[0])
    except Exception as e:
        pam_handle.log(f"Failed to import python module: {e}")
        return ERRORS[fn_name]

    handler = getattr(module, fn_name, None)
    if handler is None:
        pam_handle.log(f"No python handler provided for {fn_name}")
        return ERRORS[fn_name]

    try:
        retval = handler(pam_handle, flags, args[1:])
    except Exception as e:
        pam_handle.log(f"Exception ocurred while running python handler: [flags={flags}, args={args[1:]}, fn_name={fn_name}]" +
                       f"   Exception: {e}")
        return ERRORS[fn_name]

    if not isinstance(retval, int):
        pam_handle.log(f"Return value must be an integer, received {type(retval)} [value={retval}]")
        return ERRORS[fn_name]
    else:
        return retval
