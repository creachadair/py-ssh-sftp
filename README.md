# SSH and SFTP Clients

This repository implements a Python wrapper around the SSH command-line tool,
and an SFTP client that can use that wrapper.

Example:

```python
from sftpclient import SFTP

with SFTP('localhost', password='secret').start() as s:
   print '\n'.join(p for p in s.listdir() if not p.startswith('.'))
```

The `sftpclient` module provides an `SFTP` class that implements a client for
the SFTP protocol.

The `sshclient` module implements a wrapper for the `ssh` command-line tool
that can be use as a transport for the `SFTP` class.
