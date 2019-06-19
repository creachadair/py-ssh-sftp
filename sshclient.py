##
## Name:     sshclient.py
## Purpose:  Wrapper for OpenSSH command-line tool.
##
## Copyright (c) 2009 Michael J. Fromberger, All Rights Reserved.
##

import getpass, os, threading, select
import runpty


class SSH(object):
    """Interface to the SSH command-line tool.

    Usage:
      ssh = SSH('hostname', subsystem = 'sftp', User = 'myname')
      ssh.start()
      ...
      ssh.stop()

    Attributes:
      ssh.child_pid   -- the process ID of the SSH subprocess.
      ssh.input_fd    -- file descriptor of child's standard input.
      ssh.output_fd   -- file descriptor of child's standard output.
      ssh.pty_fd      -- file descriptor of child's pseudo-terminal.

    While running, a thread monitors input from pty_fd and passes any
    informational queries to the .query() method, whose return value
    is passed back to SSH through the pty.
    """

    def __init__(self, host, *args, **opts):
        """Set up an SSH wrapper.  Positional arguments are passed as the
        remote command; keyword arguments are used to set values.  Certain
        keyword arguments are special, these are:

        ssh_path    -- if present, use explicit path to SSH executable.
        subsystem   -- if present, request the named subsystem.
        verbose     -- if present, request verbose output.
        ssh_options -- if present, a dictionary of SSH options.
        password    -- if present, a string giving the user's password.
        host_ok     -- if present, the default answer to host key queries.
        tty         -- if true, force a TTY to be allocated; if false, force a
                       TTY not to be allocated.  If absent, the default is
                       used.

        All other keyword arguments should match the spelling of SSH options
        from the ssh_config manual page, e.g., "Port", "User".
        """
        self._host = host

        self._passwd = opts.pop('password', None)
        self._hostok = opts.pop('host_ok', None)

        self._argv = self._getargv(host, args, opts)
        self._pid = None  # child process PID
        self._pty = None  # file descriptor to pty
        self._head = None  # file descriptor to SSH stdin
        self._tail = None  # file descriptor to SSH stdout
        self._pmon = None  # pty monitor thread

    @property
    def child_pid(self):
        "The process ID of the SSH subprocess."
        return self._pid

    @property
    def pty_fd(self):
        "The file descriptor for the SSH pty."
        return self._pty

    @property
    def input_fd(self):
        "The file descriptor connected to SSH stdin."
        return self._head

    @property
    def output_fd(self):
        "The file descriptor connected to SSH stdout."
        return self._tail

    def clone(self):
        """Make a new unconnected clone using the current settings."""
        out = type(self)(self._host)
        out._host = self._host
        out._argv = self._argv
        return out

    def start(self):
        """Start up the SSH subprocess."""
        pid, pty, head, tail = runpty.run_with_pty(self._argv)
        self._pid = pid
        self._pty = pty
        self._head = head
        self._tail = tail
        self._pmon = threading.Thread(name="pty_monitor", target=self._monitor)

        self._pmon.daemon = True
        self._pmon.start()
        return self

    def stop(self):
        """Shut down the SSH subprocess."""
        if self._pid is not None:
            try:
                os.close(self._head)
            except OSError:
                pass
            try:
                os.close(self._tail)
            except OSError:
                pass
            try:
                os.close(self._pty)
            except OSError:
                pass
            self._pmon.join()
            try:
                return os.waitpid(self._pid, 0)[1]
            except OSError:
                return -1
            finally:
                self._pid = None

    def query(self, message):
        """Answer a query for information from the SSH tool.  A
        subclass may override this method to customize the behaviour.

        If the return value of this method is:

        None    -- the query is ignored.
        string  -- the string is written as a reply.
        """
        msg = message.lower().strip()
        if msg.endswith('password:') and self._passwd is not None:
            return self._passwd
        elif 'authenticity of host' in msg and self._hostok is not None:
            return self._hostok
        else:
            return getpass.getpass(message)

    def _monitor(self):
        """[private] Monitor the pseudo-tty and dispatch queries to
        the .query() method.
        """
        query = []
        sleep = None
        pty = self._pty
        while True:
            try:
                rds, wds, eds = select.select([pty], (), (), sleep)
            except select.error:
                # This usually means "bad file descriptor"
                break

            # Either there is data, or the pty is closed.
            if pty in rds:
                chunk = os.read(pty, 1024)
                if not chunk: break  # EOF
                query.append(chunk)
                sleep = 0.1
                continue

            # We get here if select times out, meaning we haven't
            # gotten anything new in "a while".
            #
            # We'll dispatch a query if it ends with ":" or "?".
            # This is SSH-specific, but it works ok.
            elif query:
                msg = b''.join(query).decode('utf8')

                if msg.rstrip()[-1:] in ('?', ':'):
                    rsp = self.query(msg)

                    if rsp is not None:
                        os.write(pty, rsp.encode('utf8'))

                        # Make sure the reply has a line break.
                        if '\n' not in rsp[-2:]:
                            os.write(pty, b'\n')

                query = []

            # Wait for something to change.
            sleep = None

    @classmethod
    def _getargv(cls, host, args, opts):
        """[private] Construct an argument vector from the options
        that were passed in to the constructor.
        """

        def OV(v):
            if v is True: return "yes"
            elif v is False: return "no"
            elif isinstance(v, (list, tuple)):
                return '"%s"' % ','.join(str(s) for s in v)
            else:
                return '"%s"' % v

        argv = [opts.pop('ssh_path', "ssh")]
        cmd = args

        if 'ssh_options' in opts:
            opts.update(opts.pop('ssh_options'))
        t = int(opts.pop('verbose', 0))
        if t:
            argv.append("-" + "v" * t)
        if 'subsystem' in opts:
            argv.append("-s")
            cmd = [opts.pop('subsystem')]
        if 'User' in opts:
            argv.extend(("-l", opts.pop('User')))
        if 'tty' in opts:
            argv.append('-' + ('t' if opts.pop('tty') else 'T'))

        for key, value in opts.items():
            argv.append("-o%s=%s" % (key, OV(value)))

        argv.append(host)
        argv.extend(cmd)
        return argv


__all__ = ("SSH",)

# Here there be dragons
