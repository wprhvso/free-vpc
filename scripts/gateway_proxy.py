import socket
import select
import threading
import sys

listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 30080

def handle_client(client_sock):
    target_sock = None
    try:
        header_buf = b""
        client_sock.settimeout(2.0)
        while b"\r\n\r\n" not in header_buf and len(header_buf) < 16384:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            header_buf += chunk
        client_sock.settimeout(None)

        if not header_buf:
            client_sock.close()
            return

        for fam, addr in [(socket.AF_INET6, ("::1", target_port, 0, 0)), (socket.AF_INET, ("127.0.0.1", target_port))]:
            try:
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(addr)
                s.settimeout(None)
                target_sock = s
                break
            except Exception:
                try:
                    s.close()
                except:
                    pass

        if target_sock is None:
            html = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Connection: close\r\n\r\n"
                b"<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"3\"><title>Free VPC</title></head>"
                b"<body style=\"font-family:sans-serif;background:#0b0f19;color:#fff;padding:50px;text-align:center;\">"
                b"<h2>Free VPC Platform Initializing...</h2>"
                b"<p>Envoy Gateway and control plane services are starting up. This page will refresh automatically in 3 seconds.</p>"
                b"</body></html>\r\n"
            )
            client_sock.sendall(html)
            return

        target_sock.sendall(header_buf)
        sockets = [client_sock, target_sock]
        while True:
            r, _, _ = select.select(sockets, [], sockets, 60)
            if not r:
                break
            for s in r:
                other = target_sock if s is client_sock else client_sock
                data = s.recv(32768)
                if not data:
                    return
                other.sendall(data)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass
        if target_sock:
            try:
                target_sock.close()
            except:
                pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen_port))
    server.listen(128)
    while True:
        try:
            sock, _ = server.accept()
            threading.Thread(target=handle_client, args=(sock,), daemon=True).start()
        except Exception:
            break

if __name__ == "__main__":
    main()
