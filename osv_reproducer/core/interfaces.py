"""
    Interface for handlers
"""

from cement import Interface, Handler


class HandlersInterface(Interface):
    """
        Handlers' Interface
    """
    class Meta:
        """
            Meta class
        """
        interface = 'handlers'
