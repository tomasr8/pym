#cython: language_level=3
import sys
from libc.stdlib cimport malloc, free
sys.path.insert(0, ".")
import importlib
from dataclasses import dataclass
from typing import Union, List
import cython
import syslog
from pathlib import Path


cdef extern from "<security/pam_appl.h>":
    pass

cdef extern from "<security/pam_modules.h>":
    # Return values
    cdef int PAM_SUCCESS
    cdef int PAM_OPEN_ERR
    cdef int PAM_SYMBOL_ERR
    cdef int PAM_SERVICE_ERRE
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
    # Linux-Pam message style extensions
    cdef int PAM_RADIO_TYPE
    cdef int PAM_BINARY_PROMPT
    # Linux-PAM pam_set_data cleanup error_status
    cdef int PAM_DATA_REPLACE
    cdef int PAM_DATA_SILENT


    cdef struct pam_message:
        int msg_style
        const char *msg
    cdef struct pam_response:
        char *resp
        int resp_retcode
    cdef struct pam_conv:
        int (*conv)(int, const pam_message **, pam_response **, void *)
        void *appdata_ptr
    cdef struct pam_xauth_data:
        int namelen
        char *name
        int datalen
        char *data
    ctypedef struct pam_handle_t:
        pass
    int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
    int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
    int pam_get_user(const pam_handle_t *pamh, const char **user, const char *prompt)
    int pam_fail_delay(pam_handle_t *pamh, unsigned int usec)
    const char *pam_strerror(pam_handle_t *pamh, int err_num)
    void pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)


cdef class PamLogger:
    cdef pam_handle_t *_pamh

    cdef set_handle(self, pam_handle_t *pamh):
        self._pamh = pamh

    @staticmethod
    cdef create(pam_handle_t *pamh):
        logger = PamLogger()
        logger.set_handle(pamh)
        return logger

    cdef log(self, msg, priority=syslog.LOG_ERR):
        print(msg)
        pam_syslog(self._pamh, priority, msg)

    cdef debug(self, msg):
        self.log(msg, priority=syslog.LOG_DEBUG)


class PamException(Exception):
    def __init__(self, err_num, description, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.err_num = err_num
        self.description = description

    def __str__(self):
        return f"PamException<{self.err_num}, {self.description}>"


@dataclass
class XAuthData:
    name: str
    data: str

    # https://stackoverflow.com/questions/56079419/using-dataclasses-with-cython
    # https://github.com/cython/cython/issues/2552
    __annotations__ = {
        'name': str,
        'data': str,
    }

@dataclass
class Message:
    msg_style: int
    msg: str

    __annotations__ = {
        'msg_style': int,
        'msg': str,
    }

@dataclass
class Response:
    resp: str
    resp_retcode: int

    __annotations__ = {
        'resp': str,
        'resp_retcode': int,
    }



cdef class PamHandle:
    cdef pam_handle_t *_pamh
    PamException = PamException
    XAuthData = XAuthData
    Message = Message
    Response = Response
    logger: PamLogger

    # Return values
    PAM_SUCCESS                = PAM_SUCCESS
    PAM_OPEN_ERR               = PAM_OPEN_ERR
    PAM_SYMBOL_ERR             = PAM_SYMBOL_ERR
    PAM_SERVICE_ERRE           = PAM_SERVICE_ERRE
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
    # Linux-Pam message style extensions
    PAM_RADIO_TYPE             = PAM_RADIO_TYPE
    PAM_BINARY_PROMPT          = PAM_BINARY_PROMPT
    # Linux-PAM pam_set_data cleanup error_status
    PAM_DATA_REPLACE           = PAM_DATA_REPLACE
    PAM_DATA_SILENT            = PAM_DATA_SILENT

    cdef set_handle(self, pam_handle_t *pamh):
        self._pamh = pamh

    @staticmethod
    cdef create(pam_handle_t *pamh):
        handle = PamHandle()
        handle.set_handle(pamh)
        handle.logger = PamLogger.create(pamh)
        return handle

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
        cdef char *user
        if prompt is None:
            retval = pam_get_user(self._pamh, <const char **>&user, NULL)
        else:
            py_prompt = prompt.encode("utf-8")
            retval = pam_get_user(self._pamh, <const char **>&user, py_prompt)

        if retval != PAM_SUCCESS:
            self.logger.log(f"Failed to get user [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))
        else:
            return user.decode("utf-8")

    def fail_delay(self, usec: int):
        retval = pam_fail_delay(self._pamh, usec)
        if retval != PAM_SUCCESS:
            self.logger.log(f"Failed to set fail delay [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

    def converse(self, msgs: Union[List[Message], Message]):
        if not isinstance(msgs, list):
            msgs = [msgs]

        cdef pam_conv *conv = NULL
        retval = pam_get_item(self._pamh, PAM_CONV, <const void**>&conv)
        if retval != PAM_SUCCESS:
            self.logger.log(f"Error when getting PAM_CONV [retval={retval}] {self.strerror(retval)}")
            raise self.PamException(err_num=retval, description=self.strerror(retval))

        cdef pam_message **c_msgs = <pam_message **> malloc(len(msgs) * cython.sizeof(cython.pointer(pam_message)))
        if not c_msgs:
            self.logger.log("Failed to allocate memory for messages inside converse()")
            raise MemoryError()

        encoded_msgs = []
        for i, msg in enumerate(msgs):
            c_msgs[i] = <pam_message *> malloc(len(msgs) * sizeof(pam_message))
            c_msgs[i].msg_style = msg.msg_style
            # Keep a reference to the encoded messages so that
            # python does not garbage collect them
            encoded_msgs.append(msg.msg.encode("utf-8"))
            c_msgs[i].msg = encoded_msgs[-1]

        cdef pam_response *c_resps = NULL
        conv.conv(len(msgs), <const pam_message **>c_msgs, &c_resps, conv.appdata_ptr)
        # Deallocate c_msgs
        for i, _ in enumerate(msgs):
            free(c_msgs[i])
        free(c_msgs)

        # Convert responses ty python
        # We are also responsible for freeing the C responses
        responses = []
        for i, _ in enumerate(msgs):
            if c_resps[i].resp == NULL:
                resp = None
            else:
                resp = c_resps[i].resp.decode("utf-8")

            resp_retcode = c_resps[i].resp_retcode
            responses.append(Response(resp, resp_retcode))
            # Overwrite and free the response
            # Overwriting ensures we don't leak any sensitive data like passwords
            c_resps[i].resp[:] = 0
            free(c_resps[i].resp)
        # Free the struct array
        free(c_resps)
        return responses

    def prompt(self, msg, msg_style=PAM_PROMPT_ECHO_OFF):
        return self.converse(Message(msg_style=msg_style, msg=msg))

    def strerror(self, err_num):
        cdef const char* err = pam_strerror(self._pamh, err_num)
        return err.decode("utf-8")

    def _get_item(self, item_type):
        cdef const char *item = NULL
        cdef pam_xauth_data *xauth = NULL

        if item_type == PAM_CONV or item_type == PAM_FAIL_DELAY:
            # We don't allow accessing these items
            return None
        elif item_type == PAM_XAUTHDATA:
            retval = pam_get_item(self._pamh, PAM_XAUTHDATA, <const void **>&xauth)
            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when getting XAuthData [retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))

            namelen = xauth.namelen
            datalen = xauth.datalen
            name = xauth.name[:namelen].decode("utf-8")
            data = xauth.data[:datalen].decode("utf-8")
            return XAuthData(name, data)
        else:
            retval = pam_get_item(self._pamh, item_type, <const void **>&item)
            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when getting item [item_type={item_type}, retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))
            return item.decode("utf-8")

    def _set_item(self, item_type, item):
        cdef char* c_string = NULL
        cdef pam_xauth_data xauth

        if item_type == PAM_CONV or item_type == PAM_FAIL_DELAY:
            # We don't allow setting these items
            # Use fail_delay() or converse() instead
            pass
        elif item_type == PAM_XAUTHDATA:
            xauth.namelen = len(item.name)
            xauth.datalen = len(item.data)
            name_bytes = item.name.encode("utf-8")
            data_bytes = item.data.encode("utf-8")
            xauth.name = name_bytes
            xauth.data = data_bytes

            retval = pam_set_item(self._pamh, item_type, <const void*>&xauth)
            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when setting XAuthData [retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))
        else:
            py_byte_string = item.encode("utf-8")
            c_string = py_byte_string
            retval = pam_set_item(self._pamh, item_type, <const void*>c_string)
            if retval != PAM_SUCCESS:
                self.logger.log(f"Error when setting item [item_type={item_type}, retval={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))


def load_module(file_path):
    module_name = Path(file_path).stem
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

# Based on pam_deny.so
# https://github.com/linux-pam/linux-pam/blob/master/modules/pam_deny/pam_deny.c
ERRORS = {
    "pam_sm_authenticate": PAM_AUTH_ERR,
    "pam_sm_setcred": PAM_CRED_ERR,
    "pam_sm_acct_mgmt": PAM_AUTH_ERR,
    "pam_sm_open_session": PAM_SESSION_ERR,
    "pam_sm_close_session": PAM_SESSION_ERR,
    "pam_sm_chauthtok": PAM_AUTHTOK_ERR
}

cdef python_handle_request(pam_handle_t *pamh, int flags, int argc, const char ** argv, pam_fn_name):
    logger = PamLogger.create(pamh)
    if argc == 0:
        logger.log("No python module provided")
        return ERRORS[pam_fn_name]

    args = []
    for i in range(argc):
        args.append(argv[i].decode("utf-8"))

    logger.debug(f"Importing {args[0]}")
    try:
        module = load_module(args[0])
    except Exception as e:
        logger.log(f"Failed to import python module: {e}")
        return ERRORS[pam_fn_name]

    pam_handle = PamHandle.create(pamh)

    handler = getattr(module, pam_fn_name, None)
    if handler is None:
        logger.log(f"No python handler provided for {pam_fn_name}")
        return ERRORS[pam_fn_name]

    try:
        retval = handler(pam_handle, flags, args[1:])
    except Exception as e:
        logger.log(f"Exception ocurred while running python handler: [flags={flags}, args={args[1:]}, fn_name={pam_fn_name}]" +
                   f"   Exception: {e}")
        return ERRORS[pam_fn_name]

    if not isinstance(retval, int):
        logger.log(f"Return value must be an integer, received {type(retval)} [value={retval}]")
        return ERRORS[pam_fn_name]
    else:
        return retval        
