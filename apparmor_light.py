import os
from ctypes import c_char_p, c_int, c_ulong, pointer, cdll, POINTER, get_errno, CDLL
from ctypes.util import find_library
from random import getrandbits
from contextlib import contextmanager


class apparmor(object):
    """
    Lightweight interface for the libapparmor shared library using ctypes
    Gyorgy Demarcsek, 2017
    """

    def __init__(self):
        self._lib = CDLL(find_library('apparmor'), use_errno=True, use_last_error=True)
        self._libc = CDLL(find_library('c'), use_errno=True, use_last_error=True)

    def _get_last_error(self):
        """
        Returns strerror(errno) as a string (last error message)
        """
        return os.strerror(get_errno())

    def get_profile(self, pid):
        """
        Returns a tuple containing the current containment mode and the current profile for the given process
        """
        _func = self._lib.aa_gettaskcon
        label, mode = c_char_p(), c_char_p()
        ret = _func(c_int(pid), pointer(label), pointer(mode))
        if ret > 0:
            return mode.value, label.value
        else:
            raise OSError(self._get_last_error())

    def get_current_profile(self):
        """
        Returns the current confinement mode and profile for the current process
        """
        return self.get_profile(os.getpid())

    def change_hat(self, profile, token=None):
        """
        Attempts to change hat (transition to a subprofile). If the token is not given it is auto-generated
        """
        _func = self._lib.aa_change_hat
        _func.restype = c_int
        subprofile = c_char_p(str(profile))
        if token is None:
            token = c_ulong(getrandbits(64))
        else:
            token = c_ulong(token)
        ret = _func(subprofile, token)
        if ret == 0:
            return token.value
        elif ret == -1:
            raise OSError(self._get_last_error())

    def escape_hat(self, token):
        """
        Attempts to change back to the previous hat
        """
        return self.change_hat(None, token=token)

    def change_profile(self, profile):
        _func = self._lib.aa_change_profile
        _func.restype = c_int
        profile_string = c_char_ptr(profile)
        ret = _func(profile_string)
        if ret < 0:
            raise OSError(self._get_last_error())

    @contextmanager
    def jail(self, hat):
        """
        A simple hat-changing context manager
        """
        token = self.change_hat(hat)
        yield
        self.escape_hat(token)
        token = 0
