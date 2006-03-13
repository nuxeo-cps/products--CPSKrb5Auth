
from zope.interface import Interface

class IKrb5Auth(Interface):
    """Identifies authenticated users during traversal and simulates the HTTP
    auth headers.
    """
