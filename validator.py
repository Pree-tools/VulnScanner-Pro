import socket
import ipaddress


def resolve_target(target):
    """
    Accepts either an IP address or a hostname.
    Returns the resolved IP address.
    """

    try:
        # Check if the input is already an IP
        ipaddress.ip_address(target)
        return target

    except ValueError:
        try:
            # Convert hostname to IP
            return socket.gethostbyname(target)

        except socket.gaierror:
            return None