#!/usr/bin/env python3
"""Loopback-only SSH/SFTP fixture for the Mini SFTP lab."""

import argparse
import getpass
import os
import pwd
import socket
import sys
import tempfile


def bind_loopback(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen()
    except OSError:
        listener.close()
        raise
    return listener


def drop_privileges(uid):
    user = pwd.getpwuid(uid)
    os.initgroups(user.pw_name, user.pw_gid)
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)


def serve(listener, password, reject=None):
    import paramiko

    class PasswordServer(paramiko.ServerInterface):
        def get_banner(self):
            return "Mini SFTP lab test server", "en"

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, supplied):
            if username == "lab" and supplied == password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind, channel_id):
            if kind == "session" and reject != "channel":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_subsystem_request(self, channel, name):
            if reject == "subsystem":
                return False
            return super().check_channel_subsystem_request(channel, name)

    class LabFiles(paramiko.SFTPServerInterface):
        def __init__(self, server, directory_fd):
            super().__init__(server)
            self.directory_fd = directory_fd

        def open(self, path, flags, attr):
            if not path or path in (".", "..") or "/" in path or "\0" in path:
                return paramiko.SFTP_PERMISSION_DENIED

            mode = 0o600 if attr.st_mode is None else attr.st_mode & 0o700
            access = flags & os.O_ACCMODE
            file_mode = {os.O_RDONLY: "rb", os.O_WRONLY: "wb", os.O_RDWR: "r+b"}
            fd = None
            try:
                fd = os.open(path, flags | os.O_NOFOLLOW, mode, dir_fd=self.directory_fd)
                handle = paramiko.SFTPHandle(flags)
                opened = os.fdopen(fd, file_mode[access])
                fd = None
                if access != os.O_WRONLY:
                    handle.readfile = opened
                if access != os.O_RDONLY:
                    handle.writefile = opened
                return handle
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            finally:
                if fd is not None:
                    os.close(fd)

    host_key = paramiko.RSAKey.generate(2048)
    with tempfile.TemporaryDirectory(prefix="mini-sftp-remote-") as directory:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            print(f"Listening on 127.0.0.1:{listener.getsockname()[1]} as lab", flush=True)
            while True:
                connection, _ = listener.accept()
                with connection, paramiko.Transport(
                    connection, default_window_size=32768, default_max_packet_size=4096
                ) as transport:
                    options = transport.get_security_options()
                    options.kex = ("diffie-hellman-group1-sha1",)
                    options.key_types = ("ssh-rsa",)
                    options.ciphers = ("aes256-cbc",)
                    options.digests = ("hmac-sha1",)
                    options.compression = ("none",)
                    transport.add_server_key(host_key)
                    transport.set_subsystem_handler(
                        "sftp", paramiko.SFTPServer, LabFiles, directory_fd=directory_fd
                    )
                    try:
                        transport.start_server(server=PasswordServer())
                        channel = transport.accept(30)
                        if channel is not None:
                            # Keep the channel alive while the subsystem handles requests.
                            transport.join()
                            channel.close()
                    except (EOFError, OSError, paramiko.SSHException) as error:
                        print(f"Connection ended: {error}", file=sys.stderr)
        finally:
            os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not sys.stdin.isatty():
        parser.error("run from a terminal to enter the experiment password")

    uid = None
    if os.geteuid() == 0:
        if not sys.flags.no_site:
            parser.error("when using sudo, invoke Python with -ISB")
        uid = int(os.environ.get("SUDO_UID", "0"))
        if uid == 0:
            parser.error("start with sudo from an unprivileged account")

    try:
        with bind_loopback(args.port) as listener:
            if uid is not None:
                drop_privileges(uid)
                import site
                site.main()
            password = getpass.getpass("Set a temporary lab password: ")
            if not password or len(password.encode()) > 99:
                parser.error("use a password of 1 to 99 UTF-8 bytes")
            serve(listener, password)
    except KeyboardInterrupt:
        return 0
    except OSError as error:
        print(f"Lab server: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
