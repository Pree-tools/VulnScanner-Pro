import socket
import ssl


def clean_banner(text):
    """Remove non-printable characters and limit length."""
    text = "".join(ch for ch in text if ch.isprintable())

    if len(text) > 100:
        text = text[:100] + "..."

    return text


def grab_banner(ip, port):

    try:

        # ---------------- HTTP ----------------
        if port in [80, 8080]:

            s = socket.socket()
            s.settimeout(3)
            s.connect((ip, port))

            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                "Connection: close\r\n\r\n"
            )

            s.send(request.encode())

            response = s.recv(4096).decode(errors="ignore")

            s.close()

            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return clean_banner(line)

            return "HTTP Server"

        # ---------------- HTTPS ----------------
        elif port == 443:

            context = ssl.create_default_context()

            sock = socket.create_connection((ip, port), timeout=3)

            ssock = context.wrap_socket(sock, server_hostname=ip)

            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                "Connection: close\r\n\r\n"
            )

            ssock.send(request.encode())

            response = ssock.recv(4096).decode(errors="ignore")

            ssock.close()

            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return clean_banner(line)

            return "HTTPS Server"

        # ---------------- SSH ----------------
        elif port == 22:

            s = socket.socket()
            s.settimeout(3)
            s.connect((ip, port))

            banner = s.recv(1024).decode(errors="ignore")

            s.close()

            return clean_banner(banner)

        # ---------------- FTP ----------------
        elif port == 21:

            s = socket.socket()
            s.settimeout(3)
            s.connect((ip, port))

            banner = s.recv(1024).decode(errors="ignore")

            s.close()

            return clean_banner(banner)

        # -------- Other Services --------
        else:
            return "Not Supported"

    except Exception:
        return "Unavailable"