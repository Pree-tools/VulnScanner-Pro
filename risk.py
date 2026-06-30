HIGH_RISK = {
    21: "FTP",
    23: "TELNET",
    445: "SMB",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MYSQL"
}

MEDIUM_RISK = {
    80: "HTTP",
    8080: "HTTP-ALT",
    25: "SMTP",
    53: "DNS"
}


def get_risk(port):

    if port in HIGH_RISK:
        return "HIGH"

    elif port in MEDIUM_RISK:
        return "MEDIUM"

    else:
        return "LOW"