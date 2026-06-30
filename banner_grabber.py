import socket
import ssl


def grab_banner(ip, port):

    try:

        # HTTP
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
                    return line

            return "HTTP Server Found"

        # HTTPS
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
                    return line

            return "HTTPS Server Found"

        # Everything else
        else:

            s = socket.socket()

            s.settimeout(3)

            s.connect((ip, port))

            banner = s.recv(1024).decode(errors="ignore").strip()

            s.close()

            if banner:
                return banner

            return "No Banner"

    except Exception:

        return "Unavailable"