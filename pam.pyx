#cython: language_level=3
import sys
from libc.stdlib cimport malloc, free
sys.path.insert(0, ".")
import importlib
from dataclasses import dataclass
from typing import Union, List
import cython
import syslog
# from pam_wrapper import XAuthData, Response, Message


cdef extern from "<security/pam_appl.h>":
    pass

cdef extern from "<security/pam_modules.h>":
    # authentication results
    cdef int PAM_AUTH_ERR
    cdef int PAM_CRED_INSUFFICIENT
    cdef int PAM_AUTHINFO_UNAVAIL
    cdef int PAM_USER_UNKNOWN
    cdef int PAM_MAXTRIES
    # pam_[gs]et_item results
    cdef int PAM_BAD_ITEM
    cdef int PAM_BUF_ERR
    cdef int PAM_SUCCESS
    cdef int PAM_PERM_DENIED
    cdef int PAM_SYSTEM_ERR
    # pam_[gs]et_item item_type
    cdef int PAM_SERVICE
    cdef int PAM_USER
    cdef int PAM_USER_PROMPT
    cdef int PAM_TTY
    cdef int PAM_RUSER
    cdef int PAM_RHOST
    cdef int PAM_AUTHTOK
    cdef int PAM_OLDAUTHTOK
    cdef int PAM_CONV
    # non-portable item_types
    cdef int PAM_FAIL_DELAY
    cdef int PAM_XDISPLAY
    cdef int PAM_XAUTHDATA
    cdef int PAM_AUTHTOK_TYPE
    # pam_message msg_style
    cdef int PAM_PROMPT_ECHO_OFF
    cdef int PAM_PROMPT_ECHO_ON
    cdef int PAM_ERROR_MSG
    cdef int PAM_TEXT_INFO 

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


def log(msg, level=syslog.LOG_ERR):
    syslog.syslog(syslog.LOG_AUTHPRIV | level, msg)


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

    # authentication results
    PAM_AUTH_ERR          = PAM_AUTH_ERR
    PAM_CRED_INSUFFICIENT = PAM_CRED_INSUFFICIENT
    PAM_AUTHINFO_UNAVAIL  = PAM_AUTHINFO_UNAVAIL
    PAM_USER_UNKNOWN      = PAM_USER_UNKNOWN
    PAM_MAXTRIES          = PAM_MAXTRIES
    # pam_[gs]et_item results
    PAM_BAD_ITEM          = PAM_BAD_ITEM
    PAM_BUF_ERR           = PAM_BUF_ERR
    PAM_SUCCESS           = PAM_SUCCESS
    PAM_PERM_DENIED       = PAM_PERM_DENIED
    PAM_SYSTEM_ERR        = PAM_SYSTEM_ERR
    # pam_[gs]et_item item_type
    PAM_SERVICE           = PAM_SERVICE
    PAM_USER              = PAM_USER
    PAM_USER_PROMPT       = PAM_USER_PROMPT
    PAM_TTY               = PAM_TTY
    PAM_RUSER             = PAM_RUSER
    PAM_RHOST             = PAM_RHOST
    PAM_AUTHTOK           = PAM_AUTHTOK
    PAM_OLDAUTHTOK        = PAM_OLDAUTHTOK
    PAM_CONV              = PAM_CONV
    # non-portable item_types
    PAM_FAIL_DELAY        = PAM_FAIL_DELAY
    PAM_XDISPLAY          = PAM_XDISPLAY
    PAM_XAUTHDATA         = PAM_XAUTHDATA
    PAM_AUTHTOK_TYPE      = PAM_AUTHTOK_TYPE
    # pam_message msg_style
    PAM_PROMPT_ECHO_OFF   = PAM_PROMPT_ECHO_OFF
    PAM_PROMPT_ECHO_ON    = PAM_PROMPT_ECHO_ON
    PAM_ERROR_MSG         = PAM_ERROR_MSG
    PAM_TEXT_INFO         = PAM_TEXT_INFO 

    cdef set_handle(self, pam_handle_t *pamh):
        self._pamh = pamh

    @classmethod
    cdef create(cls, pam_handle_t *pamh):
        handle = cls()
        handle.set_handle(pamh)
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

    def _get_item(self, item_type):
        print("getting", item_type)
        cdef const char *item = NULL
        cdef pam_xauth_data *xauth = NULL
        if item_type == PAM_CONV:
            return None
        elif item_type == PAM_FAIL_DELAY:
            return None
        elif item_type == PAM_XAUTHDATA:
            retval = pam_get_item(self._pamh, PAM_XAUTHDATA, <const void **>&xauth)
            if retval != PAM_SUCCESS:
                log(f"pam_get_item: [err_num={retval}] {self.strerror(retval)}")
                raise self.PamException(err_num=retval, description=self.strerror(retval))
            namelen = xauth.namelen
            datalen = xauth.datalen

            name = xauth.name[:namelen].decode("utf-8")
            data = xauth.data[:datalen].decode("utf-8")

            xauth_wrapper = XAuthData(name, data)
            return xauth_wrapper

        else:
            retval = pam_get_item(self._pamh, item_type, <const void **>&item)
            if retval != PAM_SUCCESS:
                raise self.PamException(err_num=retval, description=self.strerror(retval))
            value = item.decode("utf-8")
            print("VALUE", item_type, value)
            return value

    def _set_item(self, item_type, item):
        print("setting item", item_type, item)
        cdef char* c_string = NULL
        cdef pam_xauth_data xauth
        if item_type == PAM_CONV:
            pass
        elif item_type == PAM_FAIL_DELAY:
            pass
        elif item_type == PAM_XAUTHDATA:
            xauth.namelen = len(item.name)
            py_byte_string_name = item.name.encode("utf-8")
            xauth.name = py_byte_string_name
            
            xauth.datalen = len(item.data)
            py_byte_string_data = item.data.encode("utf-8")
            xauth.data = py_byte_string_data

            retval = pam_set_item(self._pamh, item_type, <const void*>&xauth)
            if retval != PAM_SUCCESS:
                raise self.PamException(err_num=retval, description=self.strerror(retval))
        else:
            py_byte_string = item.encode("utf-8")
            c_string = py_byte_string
            retval = pam_set_item(self._pamh, item_type, <const void*>c_string)
            if retval != PAM_SUCCESS:
                raise self.PamException(err_num=retval, description=self.strerror(retval))

    def get_user(self, prompt=None):
        cdef char *user
        if prompt is None:
            retval = pam_get_user(self._pamh, <const char **>&user, NULL)
        else:
            py_prompt = prompt.encode("utf-8")
            retval = pam_get_user(self._pamh, <const char **>&user, py_prompt)

        if retval != PAM_SUCCESS:
                raise self.PamException(err_num=retval, description=self.strerror(retval))
        return user.decode("utf-8")

    def fail_delay(self, usec: int):
        retval = pam_fail_delay(self._pamh, usec)
        if retval != PAM_SUCCESS:
            raise self.PamException(err_num=retval, description=self.strerror(retval))

    def conversation(self, msgs: Union[List[Message], Message]):
        if not isinstance(msgs, list):
            msgs = [msgs]
        cdef pam_conv *conv = NULL
        retval = pam_get_item(self._pamh, PAM_CONV, <const void**>&conv)
        if retval != PAM_SUCCESS:
            raise self.PamException(err_num=retval, description=self.strerror(retval))

        cdef pam_message **c_msgs = <pam_message **> malloc(len(msgs) * cython.sizeof(cython.pointer(pam_message)))
        if not c_msgs:
            raise MemoryError()

        encoded_msgs = []
        for i, msg in enumerate(msgs):
            c_msgs[i] = <pam_message *> malloc(len(msgs) * sizeof(pam_message))
            c_msgs[i].msg_style = msg.msg_style
            encoded_msgs.append(msg.msg.encode("utf-8"))
            c_msgs[i].msg = encoded_msgs[-1]

        cdef pam_response *c_resp = NULL
        conv.conv(len(msgs), <const pam_message **>c_msgs, &c_resp, conv.appdata_ptr)
        for i, _ in enumerate(msgs):
            free(c_msgs[i])
        free(c_msgs)

        responses = []
        for i, _ in enumerate(msgs):
            if c_resp[i].resp == NULL:
                resp = None
            else:
                resp = c_resp[i].resp.decode("utf-8")
            resp_retcode = c_resp[i].resp_retcode
            responses.append(Response(resp, resp_retcode))
            free(c_resp[i].resp)
        free(c_resp)
        return responses

    def strerror(self, err_num):
        cdef const char* err = pam_strerror(self._pamh, err_num)
        return err.decode("utf-8")


cdef python_handle_request(pam_handle_t *pamh, int flags, int argc, const char ** argv, pam_fn_name):
    if argc == 0:
        log("pym: no python module provided")
        return PAM_AUTH_ERR

    args = []
    for i in range(argc):
        args.append(argv[i].decode("utf-8"))

    print("importing", args[0])
    try:
        module = importlib.import_module(args[0])
    except ImportError as e:
        log(str(e))
        return PAM_AUTH_ERR

    pam_handle = PamHandle.create(pamh)

    try:
        getattr(module, pam_fn_name)(pam_handle, flags, args[1:])
    except Exception as e:
        log(str(e))
        return PAM_AUTH_ERR


# cdef public int python_pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char ** argv):
#     return handle_request(pamh, flags, argc, argv, "pam_sm_authenticate")


# cdef public int python_pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char ** argv):
#     return handle_request(pamh, flags, argc, argv, "pam_sm_setcred")


# cdef public int python_pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char ** argv):
#     return handle_request(pamh, flags, argc, argv, "pam_sm_acct_mgmt")


# cdef public int python_pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char ** argv):
#     return handle_request(pamh, flags, argc, argv, "pam_sm_open_session")


# cdef public int python_pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char ** argv):
#     return handle_request(pamh, flags, argc, argv, "pam_sm_close_session")


# cdef public int python_pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char ** argv):
#     return handle_request(pamh, flags, argc, argv, "pam_sm_chauthtok")


# cdef public void process_handle(pam_handle_t *pamh):
#     print("processing!")

#     p = PamHandle()
#     p.set_handle(pamh)
#     p.user
#     try:
#         p._get_item(123)
#     except PamHandle.PamException as e:
#         print("ERROR", e.err_num, e.description)

#     try:
#         p.xauthdata
#     except PamHandle.PamException as e:
#         print("ERROR", e.err_num, e.description)


#     p.xauthdata = XAuthData("denis", "some_other_data")

#     try:
#         p.xauthdata
#     except PamHandle.PamException as e:
#         print("ERROR", e.err_num, e.description)

#     print("CONVERSE")
#     resp = p.conversation([Message(PAM_TEXT_INFO, "Initializing..."), Message(PAM_PROMPT_ECHO_ON, "Password:\n")])
#     print("resp", resp)

#     print("getting user..")
#     print(p.get_user())
