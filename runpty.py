##
## Name:     runpty.py
## Purpose:  Run a subprocess with a pseudo-terminal.
##
## Copyright (c) 2009 Michael J. Fromberger, All Rights Reserved.
##

import os, signal


def run_with_pty(argv, path=None):
    """Run the specified program in a child process with a pseudo-
    terminal.  If path is specified, it will be used as the executable
    path; otherwise, the first argument will be used and the
    environment searched.

    Returns a tuple (pid, pty, head, tail), where:

    pid   -- the process ID of the child process.
    pty   -- the controlling terminal of the child (read/write fd).
    head  -- the child's standard input (writable fd).
    tail  -- the child's standard output (readable fd).
    """
    master, slave = os.openpty()

    headr, headw = os.pipe()
    tailr, tailw = os.pipe()

    pid = os.fork()
    if pid == 0:
        # -- This is the child process
        os.close(master)

        # Drop controlling terminal; become session leader.
        os.setsid()

        # Acquire pty as new controlling terminal.
        pty = os.open(os.ttyname(slave), os.O_RDWR)

        # Hook up standard I/O channels.
        os.dup2(headr, 0)
        os.close(headr)
        os.close(headw)
        os.dup2(tailw, 1)
        os.close(tailr)
        os.close(tailw)
        os.dup2(pty, 2)
        os.close(pty)

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        if path is None:
            os.execvp(argv[0], argv)
        else:
            os.execv(path, argv)

        # Control will not reach here unless exec fails.
        os._exit(-1)

    else:
        # -- This is the parent process
        os.close(headr)
        os.close(tailw)
        os.close(slave)

        return pid, master, headw, tailr


# Here there be dragons
