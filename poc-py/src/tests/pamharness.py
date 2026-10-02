"""A minimal PAM client over ctypes, so tests can run pam_authenticate for real.

pam_start_confdir (Linux-PAM 1.4+) reads the service's files from a directory of our
choosing instead of /etc/pam.d. The real libpam and the real pam_exec.so then run the exact
control lines under test, and nothing on the system is read for configuration or changed.
"""

import ctypes
from ctypes import CFUNCTYPE, POINTER, Structure, byref, c_char_p, c_int, c_size_t, c_void_p, cast, sizeof
from dataclasses import dataclass, field
from pathlib import Path

PAM_SUCCESS = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_BUF_ERR = 5


class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class PamResponse(Structure):
    _fields_ = [("resp", c_void_p), ("resp_retcode", c_int)]


ConversationFunction = CFUNCTYPE(c_int, c_int, POINTER(POINTER(PamMessage)), POINTER(POINTER(PamResponse)), c_void_p)


class PamConversation(Structure):
    _fields_ = [("conv", ConversationFunction), ("appdata_ptr", c_void_p)]


libpam = ctypes.CDLL("libpam.so.0")
libpam.pam_start_confdir.argtypes = [c_char_p, c_char_p, POINTER(PamConversation), c_char_p, POINTER(c_void_p)]
libpam.pam_authenticate.argtypes = [c_void_p, c_int]
libpam.pam_end.argtypes = [c_void_p, c_int]

# libpam frees the responses itself, so they must come from C's allocator.
libc = ctypes.CDLL("libc.so.6")
libc.calloc.argtypes = [c_size_t, c_size_t]
libc.calloc.restype = c_void_p
libc.strdup.argtypes = [c_char_p]
libc.strdup.restype = c_void_p


@dataclass
class Attempt:
    status: int
    prompts: list[str] = field(default_factory=list)   # what PAM asked for
    messages: list[str] = field(default_factory=list)  # what PAM said without asking

    @property
    def unlocked(self) -> bool:
        return self.status == PAM_SUCCESS


@dataclass
class PamClient:
    """Authenticates one user for one service, reading the service's files from `confdir`."""

    confdir: Path
    service: str
    user: str

    def authenticate(self, typed: str) -> Attempt:
        """One unlock attempt: `typed` answers every prompt, the way a greeter's one field does."""
        attempt = Attempt(status=-1)

        def converse(count, messages, responses_out, _appdata):
            responses = libc.calloc(count, sizeof(PamResponse))
            if not responses:
                return PAM_BUF_ERR
            array = cast(responses, POINTER(PamResponse))
            for i in range(count):
                message = messages[i].contents
                text = message.msg.decode() if message.msg else ""
                if message.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                    attempt.prompts.append(text)
                    array[i].resp = libc.strdup(typed.encode())
                else:
                    attempt.messages.append(text)
            responses_out[0] = array
            return PAM_SUCCESS

        callback = ConversationFunction(converse)  # held in a local so it outlives the call
        conversation = PamConversation(callback, None)
        handle = c_void_p()
        status = libpam.pam_start_confdir(
            self.service.encode(), self.user.encode(), byref(conversation), str(self.confdir).encode(), byref(handle),
        )
        if status != PAM_SUCCESS:
            raise RuntimeError(f"pam_start_confdir failed with {status}")
        try:
            attempt.status = libpam.pam_authenticate(handle, 0)
        finally:
            libpam.pam_end(handle, attempt.status)
        return attempt
