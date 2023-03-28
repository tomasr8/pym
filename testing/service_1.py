import sys
import threading
from pam import authenticate

def fn(user):
    authenticate(user, 'b', 'test-service-1')
    
auth1 = threading.Thread(target=fn, args=('ken',))
auth2 = threading.Thread(target=fn, args=('denis',))

auth1.start()
auth2.start()

auth1.join()
auth2.join()


# name = sys.argv[1]
# authenticate(name, 'b', 'test-service-1')
