"""Lightweight TCP honeypot

Usage examples:
  python .\scripts\honeypot.py --host 127.0.0.1 --ports 2222,2323 --banner "SSH-2.0-FakeHP" --logfile honeypot.log

Notes:
- Default binds to 127.0.0.1 to avoid exposing to the public internet. If you bind to 0.0.0.0, ensure you understand the risks and have permission.
"""
import argparse
import socket
import threading
import logging
import signal
import sys
import time
import json
from datetime import datetime
from typing import List, Optional


def setup_logger(level=logging.INFO):
    logger = logging.getLogger('honeypot')
    logger.setLevel(level)
    if not logger.handlers:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
        logger.addHandler(ch)
    return logger


class Honeypot:
    def __init__(self, host: str = '127.0.0.1', ports: Optional[List[int]] = None, banner: Optional[bytes] = None,
                 logfile: Optional[str] = None, json_lines: bool = True):
        self.host = host
        self.ports = ports or [2222]
        self.banner = banner
        self.logfile = logfile
        self.json_lines = json_lines
        self.logger = setup_logger()

        self._sockets: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._client_threads: List[threading.Thread] = []
        self._shutdown = threading.Event()

        # file for structured connection logs (JSON lines)
        self._log_fd = None
        if self.logfile:
            try:
                self._log_fd = open(self.logfile, 'a', buffering=1, encoding='utf-8')
            except Exception as e:
                self.logger.error('Failed to open logfile %s: %s', self.logfile, e)
                self._log_fd = None

    def start(self):
        for port in self.ports:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, port))
                srv.listen(5)
                srv.settimeout(1.0)
                self._sockets.append(srv)
                t = threading.Thread(target=self._accept_loop, args=(srv, port), daemon=True)
                t.start()
                self._threads.append(t)
                self.logger.info('Listening on %s:%d', self.host, port)
            except PermissionError:
                self.logger.error('Permission denied binding to %s:%d (try a port >1024 or run as admin)', self.host, port)
            except OSError as e:
                self.logger.error('Failed to bind %s:%d: %s', self.host, port, e)

    def _accept_loop(self, srv_sock: socket.socket, port: int):
        while not self._shutdown.is_set():
            try:
                conn, addr = srv_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ct = threading.Thread(target=self._handle_client, args=(conn, addr, port), daemon=True)
            ct.start()
            self._client_threads.append(ct)

    def _handle_client(self, conn: socket.socket, addr, port: int):
        peer = f"{addr[0]}:{addr[1]}"
        self.logger.info('Connection from %s to port %d', peer, port)
        ts = datetime.utcnow().isoformat() + 'Z'
        try:
            if self.banner:
                try:
                    conn.sendall(self.banner + b"\r\n")
                except OSError:
                    pass
            conn.settimeout(2.0)
            try:
                data = conn.recv(8192)
            except socket.timeout:
                data = b''
            except OSError:
                data = b''

            entry = {
                'timestamp': ts,
                'peer': peer,
                'port': port,
                'banner_sent': bool(self.banner),
                'data_len': len(data) if data else 0,
            }
            # include a safe preview of data (utf-8 or hex)
            if data:
                try:
                    preview = data.decode('utf-8', errors='replace')
                    entry['data_preview'] = preview[:200]
                except Exception:
                    entry['data_hex'] = data[:200].hex()

            self._write_log(entry)

            # Respond with a lightweight prompt to keep connection alive briefly
            if data:
                try:
                    conn.sendall(b"\n#\n")
                except OSError:
                    pass
            else:
                # If no data, just wait a moment then close
                time.sleep(0.1)

        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
            self.logger.info('Closed connection from %s', peer)

    def _write_log(self, entry: dict):
        line = json.dumps(entry, ensure_ascii=False)
        # console log a short summary
        self.logger.info('Logged: %s', {k: entry[k] for k in ('peer', 'port', 'data_len') if k in entry})
        if self._log_fd:
            try:
                self._log_fd.write(line + '\n')
            except Exception as e:
                self.logger.error('Failed to write log: %s', e)

    def stop(self):
        self.logger.info('Shutting down honeypot')
        self._shutdown.set()
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
        # join threads briefly
        for t in self._threads + self._client_threads:
            t.join(timeout=1.0)
        if self._log_fd:
            try:
                self._log_fd.close()
            except Exception:
                pass
        self.logger.info('Honeypot stopped')


def parse_ports(text: str) -> List[int]:
    parts = text.split(',')
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-', 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(p))
    return sorted(set(out))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Lightweight TCP honeypot')
    parser.add_argument('--host', default='127.0.0.1', help='Bind host (default 127.0.0.1)')
    parser.add_argument('--ports', default='2222', help='Comma-separated ports or ranges (e.g. 2222,2323-2330)')
    parser.add_argument('--banner', default='', help='Optional banner string to send on connect')
    parser.add_argument('--logfile', default='honeypot.log', help='File to append JSON logs to (default honeypot.log)')
    parser.add_argument('--no-json', action='store_true', help='Do not write JSON lines (only console logs)')
    args = parser.parse_args(argv)

    ports = parse_ports(args.ports)
    banner = args.banner.encode() if args.banner else None
    hp = Honeypot(host=args.host, ports=ports, banner=banner, logfile=(None if args.no_json else args.logfile))

    def _sig(signum, frame):
        hp.stop()

    signal.signal(signal.SIGINT, _sig)
    try:
        hp.start()
        # keep main thread alive until shutdown
        while not hp._shutdown.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        hp.stop()


if __name__ == '__main__':
    main()
