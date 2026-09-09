"""
SNIDS controlled test server.

A minimal, dependency-free TCP listener used to generate safe, controlled
traffic against your own machine for SNIDS validation. Unlike Docker (which
can go down or lose its WSL integration), this runs directly on your host
with no external dependency, and it accepts connections in a loop instead
of exiting after the first one.

Usage:
    python3 src/detection/docker_test_server.py [host] [port]

Defaults to 0.0.0.0:9000.
"""

import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(20)

    print(f"SNIDS test server listening on {HOST}:{PORT}", flush=True)

    try:
        while True:
            conn, addr = server.accept()
            print(f"Connected by {addr}", flush=True)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except Exception as error:
                print(f"Connection error: {error}", flush=True)
            finally:
                conn.close()
                print("Connection closed.", flush=True)
    except KeyboardInterrupt:
        print("\nShutting down test server.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
