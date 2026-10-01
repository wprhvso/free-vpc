import socket
import select
import threading
import sys

listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 9002
node_num = sys.argv[3] if len(sys.argv) > 3 else "1"

def handle_client(client_sock):
    backend = None
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

        if b"upgrade: websocket" in header_buf.lower():
            backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend.settimeout(3.0)
            backend.connect(("127.0.0.1", target_port))
            backend.settimeout(None)
            backend.sendall(header_buf)

            sockets = [client_sock, backend]
            while True:
                r, _, _ = select.select(sockets, [], sockets, 60)
                if not r:
                    break
                for s in r:
                    other = backend if s is client_sock else client_sock
                    data = s.recv(32768)
                    if not data:
                        return
                    other.sendall(data)
        else:
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Connection: close\r\n\r\n"
                b"<!DOCTYPE html><html><head><title>Free VPC Mesh</title></head>"
                b"<body style=\"font-family:sans-serif;background:#0b0f19;color:#fff;padding:50px;\">"
                b"<h2>Free VPC Mesh Node " + node_num.encode() + b" Online</h2>"
                b"<p>Yggdrasil WebSocket peering endpoint is active.</p>"
                b"</body></html>\r\n"
            )
            client_sock.sendall(resp)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass
        if backend:
            try:
                backend.close()
            except:
                pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(128)
    while True:
        try:
            sock, _ = server.accept()
            threading.Thread(target=handle_client, args=(sock,), daemon=True).start()
        except Exception:
            break

if __name__ == "__main__":
    main()
