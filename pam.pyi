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
