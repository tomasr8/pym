import sys
import threading

from pam import authenticate

authenticate('ken', 'b', 'test-service-1')

