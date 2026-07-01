from colorama import Fore

def get_risk(port):

    if port in [21, 23, 445, 3389]:
        return "HIGH"

    elif port in [80, 8080]:
        return "MEDIUM"

    else:
        return "LOW"


def get_risk_color(risk):
    """Return terminal color based on risk level."""

    colors = {
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.GREEN
    }

    return colors.get(risk, Fore.WHITE)