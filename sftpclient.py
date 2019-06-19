##
## Name:     sftpclient.py
## Purpose:  SFTP client library.
##
## Copyright (c) 2009 Michael J. Fromberger, All Rights Reserved.
##

import errno, functools, os, struct, threading
import stat as os_stat
import ioqueue, sshclient, struct

# This is the protocol version we claim to support.  Don't change it
# unless you know what the hell you're doing.
SFTP_PROTOCOL_VERSION = 3


def enum(cls):
    """Make a class behave like an enumerated type by generating a reverse
    mapping for all the names defined on the class which are uppercased.
    """
    rmap = {}
    for name in dir(cls):
        if name == name.upper():
            k = cls.__name__ + "_" + name
            v = getattr(cls, name)
            if (v not in rmap or k < rmap[v]):
                rmap[v] = k

    cls.codes = rmap
    return cls


@enum
class FXP(object):
    """Enumeration for packet types."""
    INIT = 1
    VERSION = 2
    OPEN = 3
    CLOSE = 4
    READ = 5
    WRITE = 6
    LSTAT = 7
    FSTAT = 8
    SETSTAT = 9
    FSETSTAT = 10
    OPENDIR = 11
    READDIR = 12
    REMOVE = 13
    MKDIR = 14
    RMDIR = 15
    REALPATH = 16
    STAT = 17
    RENAME = 18
    READLINK = 19
    SYMLINK = 20

    STATUS = 101
    HANDLE = 102
    DATA = 103
    NAME = 104
    ATTRS = 105

    EXTENDED = 200
    EXTENDED_REPLY = 201


@enum
class FILEXFER_ATTR(object):
    """Enumeration for file attribute flags."""

    # Protocol version 3 flags
    SIZE = 0x00000001
    UIDGID = 0x00000002
    PERMISSIONS = 0x00000004
    ACMODTIME = 0x00000008
    EXTENDED = 0x80000000


@enum
class FXF(object):
    """Enumeration for file-opening flags."""
    READ = 0x00000001
    WRITE = 0x00000002
    APPEND = 0x00000004
    CREAT = 0x00000008
    CREATE = 0x00000008
    TRUNC = 0x00000010
    EXCL = 0x00000020


@enum
class FX(object):
    """Enumeration for status codes."""

    OK = 0  # success
    EOF = 1  # end of file
    NO_SUCH_FILE = 2
    PERMISSION_DENIED = 3
    FAILURE = 4  # unspecified failure
    BAD_MESSAGE = 5  # bad packet, protocol error
    NO_CONNECTION = 6  # (local only)
    CONNECTION_LOST = 7  # (local only)
    OP_UNSUPPORTED = 8


class sftp_error(Exception):
    "Base class for SFTP client exceptions."


class sftp_proto_error(sftp_error):
    "Unexpected reply from the server."


class sftp_io_error(sftp_error):
    "Unable to perform the requested I/O."


class sftp_status_error(sftp_error):
    "Unsuccessful status reply from the server."


class sbitter(object):
    """Represents a writable view of a sequenced data type such as a
    string, list, or buffer.  Operations on a bitter return a bitter,
    so that it is possible to chain calls functionally.  Furthermore,
    all operations are non-destructive.

    The important properties of a bitter are:
    .pos    -- the current position in the input.
    .source -- the input itself.
    .value  -- the value obtained by a read or set operation.
    .length -- the length of the input.

    Sources will generally be lists, tuples, or strings, but in
    principle any type that supports len, integer indexing, slicing,
    and catenation should work.
    """

    def __init__(self, source, pos=0, value=None):
        """Source may be any indexable sequence type.
        """
        self._src = source
        self._pos = slice(pos).indices(len(source))[1]
        self._val = value

    @property
    def pos(self):
        return self._pos

    @property
    def source(self):
        return self._src

    @property
    def value(self):
        return self._val

    @property
    def length(self):
        return len(self._src)

    def update(self, func, *args, **kw):
        """Update the value by applying func to the current value."""
        return type(self)(self.source, self.pos, func(self.value, *args, **kw))

    def __len__(self):
        return self.length

    def __repr__(self):
        return '#<%s @%d src[%d]=%r%s%s>' % (
            type(self).__name__, self.pos, len(self), self.source[:24],
            '+' if len(self) > 24 else '', '' if self.value is None else 'v')

    def seek(self, pos):
        """Seek to the specified absolute position, returning an sbitter.
        Use None to seek to the end.
        """
        if pos is None: pos = self.length
        if pos == self.pos: return self
        else: return type(self)(self.source, pos, self.value)

    def move(self, offset):
        """Seek relative to the current position, returning an sbitter.
        """
        if offset == 0: return self
        else: return type(self)(self.source, self.pos + offset, self.value)

    def into(self, d, key):
        """Store the value into a dictionary under the given key."""
        d[key] = self.value
        return self

    def read(self, nc=None):
        """Read up to nc elements at the current position into value.
        Set nc=None to use the value.
        """
        if nc is None: nc = self.value or 0
        d = self.source[self.pos:self.pos + nc]
        return type(self)(self.source, self.pos + len(d), d)

    def readn(self, nc=None):
        """Read exactly nc elements at the current position into value.
        Set nc=None to use the value.
        """
        if nc is None: nc = self.value or 0
        d = self.source[self.pos:self.pos + nc]
        if len(d) != nc: raise ValueError("expected %d elements" % nc)
        return type(self)(self.source, self.pos + len(d), d)

    def write(self, v=None):
        """Write elements of v at the current position.  Set v=None to
        write the value.
        """
        if v is None: v = self.value
        d = self.source[:self.pos] + v
        np = len(d)
        return type(self)(d + self.source[np:], np, self.value)

    def pack(self, fmt, *args):
        """Equivalent to self.write(struct.pack(fmt, *args)).
        """
        return self.write(struct.pack(fmt, *args))

    def unpack(self, fmt):
        """Unpack a format from the struct module into the value.
        """
        return self.readn(
            struct.calcsize(fmt)).update(lambda v: struct.unpack(fmt, v))

    def read_uint32(self):
        return self.unpack('>I').update(lambda v: v[0])

    def read_uint64(self):
        return self.unpack('>Q').update(lambda v: v[0])

    def read_sftp_str(self):
        return self.read_uint32().read(None)

    def write_uint32(self, v=None):
        if v is None: v = self.value
        return self.pack('>I', v)

    def write_uint64(self, v=None):
        if v is None: v = self.value
        return self.pack('>Q', v)

    def write_sftp_str(self, s):
        return self.write_uint32(len(s)).write(s)

    def write_sftp_strs(self, ss):
        return functools.reduce(sbitter.write_sftp_str, ss, self)


def catchkey(meth):
    """Convert KeyError thrown out of an ioqueue access and convert it
    into sftp_io_error.
    """

    def wrapper(self, *args, **kw):
        try:
            return meth(self, *args, **kw)
        except KeyError:
            raise sftp_io_error("packet unavailable")

    return functools.update_wrapper(wrapper, meth)


class sftp_core(object):
    """Low-level SFTP client, implementing basic packet I/O and request
    mechanics.  Subclasses should provide higher-level abstractions.
    """

    def __init__(self, ifd, ofd):
        """Create an SFTP client with file descriptors connected to an active
        SSH transport of some kind.

        ifd  -- input channel, receiving packets from the server.
        ofd  -- output channel, delivering packets to the server.
        """
        self.ifd = ifd
        self.ofd = ofd

        # All the actual reading and writing is done by these threads;
        # the rest of the client sends and receives packets via the
        # queue objects.

        self._rq = ioqueue.ioqueue(detach_tasks=True)
        self._rd = threading.Thread(target=self._reader, name="Reader")
        self._wq = ioqueue.ioqueue(detach_tasks=True)
        self._wr = threading.Thread(target=self._writer, name="Writer")

    def start(self):
        """Start the I/O processing threads.  This method must be called before
        any data may be read from or written to the server.
        """
        self._rd.daemon = True
        self._rd.start()
        self._wr.daemon = True
        self._wr.start()
        return self

    @catchkey
    def stop(self):
        """Close down the transport channels and stop the I/O processing
        threads.
        """
        if self._wr.is_alive():
            self._wq.push_task('stop')
            self._wr.join()
            self._wq.flush()
        try:
            os.close(self.ofd)
        except OSError:
            pass
        try:
            os.close(self.ifd)
        except OSError:
            pass
        self._rd.join()
        self._rq.flush()

    def close(self):
        """An alias for .stop()"""
        self.stop()

    def is_alive(self):
        """Return true if the I/O queues are currently active, allowing data to
        be sent and received on the underlying SSH channel.
        """
        return (self._wr.is_alive() and self._rd.is_alive())

    def put_packet(self, type, request_id, data=b''):
        """Schedule a packet to be written to the server.  This method returns
        as soon as the packet has been queued, even if it has not yet been
        actually transmitted.

        Returns the ID of the scheduled task.
        """
        if not self._wr.is_alive():
            raise sftp_io_error("writer thread is closed")
        return self._wq.add_task(
            'send', type=type, request_id=request_id, data=data)

    @catchkey
    def push_packet(self, type, request_id, data=b''):
        """Write a single packet to the server as soon as possible; this method
        blocks until the packet has been written.

        Returns the length of the data actually written.
        """
        if not self._wr.is_alive():
            raise sftp_io_error("writer thread is closed")
        return self._wq.push_task(
            'send', type=type, request_id=request_id, data=data)

    def get_any_packet(self, timeout=None):
        """Read a single packet from the server; throws KeyError if timeout is
        reached and no packet is available.
        """

        def mfunc(t):
            return t.tag == 'recv'

        return self._getpacket(mfunc, timeout)

    def put_request(self, type, request_id, data=b''):
        """Send a single request packet and wait for the corresponding
        response.  Returns the response packet.
        """
        self.put_packet(type, request_id, data)
        return self.get_request_packet(request_id)

    def get_request_packet(self, request_id, timeout=None):
        """Read the next available packet matching the given request_id; throws
        KeyError if timeout isn't None and no packet is available.
        """

        def mfunc(t):
            return t.t_request_id == request_id

        return self._getpacket(mfunc, timeout)

    def get_matching_packet(self, mfunc, timeout=None):
        """Read the next available packet matching the given function; throws
        KeyError if timeout is set and no packet is available.
        """
        return self._getpacket(mfunc, timeout)

    @catchkey
    def _getpacket(self, mfunc, timeout):
        if not self._rd.is_alive():
            raise sftp_io_error("reader thread is closed")

        req = self._rq.next_matching(mfunc, timeout)
        self._rq.task_done(req, req.t_type)
        return req.t_type, req.t_request_id, req.t_data

    def _read(self, nc):
        "[private] Read bytes from the input, throw EOFError at EOF."
        raw = os.read(self.ifd, nc)
        if not raw:
            raise EOFError
        return raw

    def _readu(self, fmt):
        """[private] Read bytes from the input to satisfy the struct format,
        and return the unpacked results.
        """
        nc = struct.calcsize(fmt)
        raw = self._read(nc)
        return struct.unpack(fmt, raw)

    def _readn(self, nc):
        """Read all requested data from the input, or throw EOFError.
        """
        data = []
        r = 0
        while r < nc:
            data.append(self._read(nc - r))
            r += len(data[-1])

        return b''.join(data)

    @classmethod
    def _datasplit(cls, fmt, raw):
        """[private] Unpack a formatted prefix from a byte string and return a
        tuple consisting of the unpacked fields plus the remainder of the
        string, if any.
        """
        nc = struct.calcsize(fmt)
        return struct.unpack_from(fmt, raw) + (raw[nc:],)

    def _write(self, data):
        "[private] Write all data to the output, or throw OSError."
        pos = 0
        while pos < len(data):
            nw = os.write(self.ofd, data[pos:])
            pos += nw

        return pos

    def _reader(self):
        """[private] Process packets from the remote server.

        When a packet is received, a "recv" task is queued with attributes:
        .t_type        -- the type code (byte).
        .t_request_id  -- the request ID (int).
        .t_data        -- the payload, possibly empty (bytes).

        The thread will exit when the input returns EOF.
        """
        try:
            while True:
                n = self._readu('>I')[0]
                data = self._readn(n)

                pt, rid, data = self._datasplit('>BI', data)
                self._rq.add_task('recv', type=pt, request_id=rid, data=data)
        except EOFError:
            pass

    def _writer(self):
        """[private] Deliver packets to the remote server.

        Takes "send" packets from the queue, uses their .t_type, .t_request_id, and .t_data
        attributes to construct a packet, and writes the packet on the wire.
        When the write is complete, the total number of bytes written becomes
        the task status.

        Upon receipt of a "stop" packet, the thread will exit; it will also
        exit if a write fails due to a broken pipe.
        """
        try:
            while True:
                req = self._wq.next_task()
                if req.tag == "stop":
                    self._wq.task_done(req, 0)
                    break

                # Build the packet:
                # uint32           length -- length excluding this field.
                # byte             type   -- packet type code.
                # byte[length - 1] data   -- payload.
                body = struct.pack('>BI', req.t_type,
                                   req.t_request_id) + req.t_data
                pack = struct.pack('>I', len(body)) + body

                nw = self._write(pack)
                self._wq.task_done(req, nw)
        except OSError:
            pass


class sftp_client(sftp_core):
    """Higher-level SFTP client.
    """

    # Maximum allowed size data for a single write request, in bytes.
    MAX_WRITE_SIZE = 2**16

    # Maximum allowed size data for a single read request, in bytes.
    MAX_READ_SIZE = 2**16

    def __init__(self, ifd, ofd):
        super(sftp_client, self).__init__(ifd, ofd)

        self._nexti = 1
        self._curwd = None

    def start(self):
        super(sftp_client, self).start()
        self.init()
        return self

    def init(self):
        """Send the client protocol number to the server, and obtain in return
        the server's protocol and supported extensions.

        After initialization, these attributes are available:
        .sftp_version    -- the server's protocol version.
        .sftp_extensions -- a dictionary of supported extensions.
        """
        self.push_packet(FXP.INIT, SFTP_PROTOCOL_VERSION)
        code, version, ext_data = self.get_any_packet()
        if code != FXP.VERSION:
            raise sftp_proto_error("init: unexpected response", code)

        self.sftp_version = version
        self.sftp_extensions = ext = {}

        p = sbitter(ext_data)
        while p.pos < len(p):
            p = p.read_sftp_str()
            key = p.value.decode('utf8')
            p = p.read_sftp_str()
            val = p.value.decode('utf8')
            ext[key] = val

    def chdir(self, path):
        """Change the current working directory."""
        wd = self.realpath(self._wdpath(path))
        if not os_stat.S_ISDIR(self.stat(wd)['mode']):
            raise OSError(errno.ENOTDIR, "not a directory", wd)
        self._curwd = wd
        return wd

    def getcwd(self):
        """Get the current working directory."""
        if self._curwd is None:
            self._curwd = self._path2path('.', FXP.REALPATH)
        return self._curwd

    def lstat(self, path):
        """Return a dictionary of file stats for the given path, or
        throws sftp_status_error.
        """
        return self._getstat(self._wdpath(path), FXP.LSTAT)

    def listdir(self, path=None):
        """Return a list of names of the objects in the directory named by
        path.
        """
        with self.opendir(self._wdpath(path, True)) as d:
            return list(
                name for name, long, attrs in d if name not in (b'.', b'..'))

    def mkdir(self, path, **attrs):
        """Create a new empty directory, with initial stat values optionally
        specified as keyword arguments.
        """
        p = sbitter(b'') \
            .write_sftp_str(self._wdpath(path)) \
            .write(self._packattrs(attrs))
        self._dostat(FXP.MKDIR, p.source)

    def open(self, path, flags='r', **attrs):
        """Open or create a file.  The file is opened with accesses described
        by the following flag characters:

        r     -- open for reading.
        w     -- open for writing.
        a     -- append writes.
        c     -- create new file.
        e     -- fail request if file exists (implies 'c').
        t     -- truncate to zero length (implies 'c').

        For any mode that implies file creation, additional keyword arguments
        may be used to specify the initial settings for a new file:

        owner -- uid of the file's owner.
        group -- gid of the file's group.
        mode  -- POSIX access permission flags.

        If these are omitted, the server will choose default values.
        """
        pflags = self._pflags(flags)
        tpath = self._wdpath(path)
        if pflags & FXF.CREATE:
            if 'mode' in attrs:
                attrs['mode'] = self.parse_mode(attrs['mode'])
            handle = self._open(tpath, pflags, attrs)
        else:
            handle = self._open(tpath, pflags)

        return sftp_file(self, handle, tpath, pflags)

    def opendir(self, path):
        """Return a sftp_dir object to read the contents of the directory at
        path, or throws sftp_status_error.
        """
        tpath = self._wdpath(path)
        code, req, data = self.put_request(FXP.OPENDIR, self._getid(),
                                           self._packstr(tpath))
        self._cktype(code, data, FXP.HANDLE)
        handle = sbitter(data).read_sftp_str().value
        return sftp_dir(self, handle, tpath)

    def readlink(self, path):
        """Return the target of a symbolic link."""
        return self._path2path(self._wdpath(path), FXP.READLINK)

    def realpath(self, path):
        """Expand the specified path to its complete form."""
        return self._path2path(self._wdpath(path), FXP.REALPATH)

    def release(self, thing):
        """Release a file or directory object."""
        if isinstance(thing, sftp_thing):
            return thing.close()
        else:
            raise TypeError("requires sftp_thing")

    def rename(self, oldpath, newpath):
        """Rename a file or directory."""
        self._path2stat(FXP.RENAME, oldpath, newpath)

    def rmdir(self, path):
        """Remove a directory."""
        self._path2stat(FXP.RMDIR, path)

    def stat(self, path):
        """Return a dictionary of file stats for the given path, or throws
        sftp_status_error.  See .setstat() for a description of the dictionary.
        """
        return self._getstat(self._wdpath(path), FXP.STAT)

    def setstat(self, path, attrs):
        """Set file stats for the given path, where attrs is a dictionary of
        attribute keys and values.  Throws sftp_status_error in case of error.

        Attribute keys understood:
        'size'   -- size of file in bytes (int).
        'owner'  -- file owner ID (int).
        'group'  -- file group ID (int).
        'mode'   -- POSIX permission flags (int).
        'atime'  -- last-access time (int).
        'mtime'  -- last-modified time (int).

        Any other keys in the dictionary are ignored.
        """
        self._setstat(self._wdpath(path), FXP.SETSTAT, attrs)

    def symlink(self, target, link):
        """Create a symbolic link named link, pointing to target."""
        p = sbitter(b'').write_sftp_strs((
            self._ckstr(target),  # note: target may NOT be a path
            self._wdpath(link)))

        self._dostat(FXP.SYMLINK, p.source)

    def unlink(self, path):
        """Unlink a file."""
        self._path2stat(FXP.REMOVE, path)

    def walk(self, path, followlinks=False, include_stat=False):
        """Emulate the behaviour of os.walk() for a path on the remote server.
        For each directory in the tree rooted at path, yields a triple (dpath,
        dnames, fnames) where

        dpath  -- the pathname of the directory
        dnames -- the names of the directories inside dpath, except . and ..
        fnames -- the names of the non-directory files inside dpath

        The caller may modify dnames to affect subsequent stages of traversal.

        If include_stat is true, each file or directory will be listed as a
        tuple (name, stat) where stat is a dictionary of file metadata.
        """
        if include_stat:
            outmap = lambda n, s: (n, s)
            pathmap = lambda p: p[0]
        else:
            outmap = lambda n, s: n
            pathmap = lambda p: p

        queue = [self._ckstr(path)]
        while queue:
            cur = queue.pop()
            dnames = []
            fnames = []
            with self.opendir(cur) as dp:
                for name, desc, attr in dp:
                    # Case 1: A directory, except "." and ".."
                    if os_stat.S_ISDIR(attr['mode']):
                        if name not in (b'.', b'..'):
                            dnames.append(outmap(name, attr))
                        continue

                    # Case 2: A symlink when followlinks is true
                    elif followlinks and os_stat.S_ISLNK(attr['mode']):
                        try:
                            s = self.stat(os.path.join(cur, name))
                            if os_stat.S_ISDIR(s['mode']):
                                dnames.append(outmap(name, attr))
                            continue
                        except sftp_status_error:
                            pass  # fallthru to Case 3

                    # Case 3: Everything else
                    fnames.append(outmap(name, attr))

            yield cur, dnames, fnames
            queue.extend(
                os.path.join(cur, pathmap(x)) for x in reversed(dnames))

    # --- Extended commands --------------------------------------------

    def posix_rename(self, oldpath, newpath):
        """[ext] Perform a POSIX rename operation."""
        self._extreq(
            "posix-rename@openssh.com",
            self._packstr(self._wdpath(oldpath), self._wdpath(newpath)))

    def statvfs(self, path):
        """[ext] Return a dictionary of VFS stat information for the given
        path.  Throws sftp_status_error if unsupported.

        The result dictionary contains:
          'f_bsize':   fundamental file system block size in bytes
          'f_frsize':  minimum allocation size in bytes
          'f_blocks':  total data blocks in the file system
          'f_bfree':   number of free blocks in the file system
          'f_bavail':  number of free blocks available to non-root users
          'f_files':   total number of files in the file system
          'f_ffree':   number of free file nodes in the file system
          'f_favail':  number of free file nodes available to non-root users
          'f_fsid':    file system ID
          'f_flag':    bitmap of mount flags
          'f_namemax': maximum allowed file name length in bytes
        """
        return self._unpackvfs(
            self._extreq("statvfs@openssh.com", self._packstr(
                self._wdpath(path))))

    @classmethod
    def _unpackvfs(cls, data):
        """[private] Unpack a statvfs() reply buffer."""
        p = sbitter(data)
        out = {}
        for fname in ('bsize', 'frsize', 'blocks', 'bfree', 'bavail', 'files',
                      'ffree', 'favail', 'fsid', 'flag', 'namemax'):
            p = p.read_uint64()
            out['f_' + fname] = p.value
        return out

    # --- Private helper methods ---------------------------------------

    def _dostat(self, op, data):
        """[private] Do a request returning only a status."""
        code, req, data = self.put_request(op, self._getid(), data)
        self._cktype(code, data)

    def _extreq(self, name, data=b''):
        """[private] Issue an extended request and return the response data, or
        throw sftp_status_error.
        """
        p = sbitter(b'') \
            .write_sftp_str(self._ckstr(name)) \
            .write(data)
        code, req, rdata = self.put_request(FXP.EXTENDED, self._getid(),
                                            p.source)
        self._cktype(code, rdata, FXP.EXTENDED_REPLY)
        return rdata

    def _getid(self):
        """[private] Return a fresh request ID."""
        try:
            return self._nexti
        finally:
            self._nexti += 1

    def _getstat(self, key, op):
        """[private] Common code shared by stat(), lstat(), fstat()."""
        code, req, data = self.put_request(op, self._getid(),
                                           self._packstr(key))
        self._cktype(code, data, FXP.ATTRS)
        return self._unpackattrs(data)

    def _open(self, path, flags, attrs={}):
        """[private] Low-level interface for open() and create().  Returns a
        handle for the opened/created file, or throws sftp_status_error.  See
        .open() for flags.
        """
        p = sbitter(b'') \
            .write_sftp_str(self._ckstr(path)) \
            .write_uint32(flags) \
            .write(self._packattrs(attrs))

        code, req, data = self.put_request(FXP.OPEN, self._getid(), p.source)

        self._cktype(code, data, FXP.HANDLE)
        return sbitter(data).read_sftp_str().value

    def _path2path(self, path, op):
        """[private] Common code for path-to-path conversions."""
        code, req, data = self.put_request(op, self._getid(),
                                           self._packstr(path))
        self._cktype(code, data, FXP.NAME)
        res = self._unpackname(data)
        return res[0][0]

    def _path2stat(self, op, *paths):
        """[private] Apply an operation that takes one or more paths and
        returns a status.
        """
        p = sbitter(b'').write_sftp_strs(self._wdpath(path) for path in paths)
        self._dostat(op, p.source)

    def _release(self, handle):
        """[private] Release a handle allocated by an OPEN or OPENDIR request.
        This is generally not called directly.
        """
        code, req, data = self.put_request(FXP.CLOSE, self._getid(),
                                           self._packstr(handle))
        self._cktype(code, data)
        return 0

    def _setstat(self, key, op, attrs):
        """[private] Common code shared by setstat() and fsetstat()."""
        packet = sbitter(b'') \
                 .write_sftp_str(self._ckstr(key)) \
                 .write(self._packattrs(attrs))
        self._dostat(op, packet.source)

    def _wdpath(self, path, use_wd=False):
        """[private] Expand relative paths using the working directory.
        """
        if path is None:
            if use_wd: return self.getcwd()
            else: raise ValueError("no path specified")
        return os.path.join(self.getcwd(), self._ckstr(path))

    @classmethod
    def _ckstr(cls, s):
        """[private] Check for a string/bytes type, encode strings."""
        if type(s) is bytes: return s
        elif type(s) is str: return s.encode('utf8')
        else: raise TypeError(s)

    @classmethod
    def _packstr(cls, *ss):
        """[private] Pack one or more strings in SFTP format."""
        return sbitter(b'').write_sftp_strs(cls._ckstr(s) for s in ss).source

    # Mapping from characters to SFTP mode bits.
    pf_map = dict(
        r=FXF.READ,
        w=FXF.WRITE,
        a=FXF.APPEND,
        c=FXF.CREAT,
        e=FXF.CREAT | FXF.EXCL,
        t=FXF.CREAT | FXF.TRUNC)

    @classmethod
    def _pflags(cls, flags):
        """[private] Translate flag characters into FXF flag bits.

        (a)ppend, (c)reate, (e)xclusive, (r)ead, (t)runcate, (w)rite
        Mode flags other than these are ignored.
        """
        result = 0
        for c in flags:
            result |= cls.pf_map.get(c, 0)
        return result

    # Mapping from mode string type characters to S_IFMT values.
    pt_map = {
        'd': os_stat.S_IFDIR,
        '-': os_stat.S_IFREG,
        'b': os_stat.S_IFBLK,
        'c': os_stat.S_IFCHR,
        'p': os_stat.S_IFIFO,
        'l': os_stat.S_IFLNK,
        's': os_stat.S_IFSOCK,
    }

    # Mapping from permission characters to bit values.
    pp_map = {
        'r': '1',
        'w': '1',
        'x': '1',
        '-': '0',
        'S': '0',
        's': '1',
        'T': '0',
        't': '1',
    }

    @classmethod
    def parse_mode(cls, mode):
        """Parse a 10-character ls-style permission string and return
        the corresponding integer mode value.
        """
        if isinstance(mode, int):
            if os_stat.S_IFMT(mode) == 0:
                return mode | os_stat.S_IFREG
            else:
                return mode
        elif not isinstance(mode, str):
            raise TypeError("mode must be int or string")
        elif len(mode) != 10:
            raise ValueError("invalid mode string", mode)

        try:
            out = int(''.join(cls.pp_map[x] for x in mode[1:]), 2)

            # Interpret setuid, segid, and sticky bits.
            if mode[3] in 'sS': out |= os_stat.S_ISUID
            if mode[6] in 'sS': out |= os_stat.S_ISGID
            if mode[9] in 'tT': out |= os_stat.S_ISVTX

            # Include file type.
            out |= cls.pt_map[mode[0]]
            return out
        except KeyError:
            raise ValueError("invalid mode string", mode)

    # Mapping from octal permissions to permission character triples.
    pc_map = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']

    # Reverse mapping from S_IFMT values to type characters.
    pt_rmap = dict((v, k) for k, v in pt_map.items())
    pt_rmap[0] = '-'

    @classmethod
    def unparse_mode(cls, mode):
        """Unparse an integer mode word into a 10-character ls-style
        permission string.
        """
        out = [cls.pt_rmap[os_stat.S_IFMT(mode)]]
        out.extend(cls.pc_map[(mode >> 6) & 7])
        out.extend(cls.pc_map[(mode >> 3) & 7])
        out.extend(cls.pc_map[(mode >> 0) & 7])

        if mode & os_stat.S_ISUID:
            out[3] = 'S' if out[3] == '-' else 's'
        if mode & os_stat.S_ISGID:
            out[6] = 'S' if out[6] == '-' else 's'
        if mode & os_stat.S_ISVTX:
            out[9] = 'T' if out[9] == '-' else 't'

        return ''.join(out)

    @classmethod
    def _unpackname(cls, data):
        """[private] Unpack a SSH_FXP_NAME response packet, returning a list of
        (name, longname, attrs) tuples.
        """
        p = sbitter(data).read_uint32()
        res = [None] * p.value
        for pos in range(len(res)):
            p = p.read_sftp_str()
            name = p.value
            p = p.read_sftp_str()
            long = p.value
            A = cls._unpackattrs(p.source[p.pos:], mark_end=True)
            p = p.move(A.pop('_end'))
            res[pos] = name, long, A
        return res

    @classmethod
    def _packattrs(cls, attrs, use_extended=False):
        """[private] Pack a dictionary of attributes into a packet payload.
        See .setstat() for a description of the dictionary.

        Standard keys: size, owner, group, mode, atime, mtime
        Any keys in the dictionary besides these are ignored unless they
        contain a '@' character and use_extended is true.  Keys and values for
        extended attributes must be of type str or byte; str values will be
        encoded as UTF-8.
        """
        A = attrs.copy()

        packet = sbitter(b'').write_uint32(0)
        flags = 0
        if 'size' in A:
            flags |= FILEXFER_ATTR.SIZE
            packet = packet.write_uint64(A.pop('size'))
        if 'owner' in A or 'group' in A:
            flags |= FILEXFER_ATTR.UIDGID
            packet = packet.write_uint32(A.pop('owner', 0))
            packet = packet.write_uint32(A.pop('group', 0))
        if 'mode' in A:
            flags |= FILEXFER_ATTR.PERMISSIONS
            packet = packet.write_uint32(A.pop('mode'))
        if 'atime' in A or 'mtime' in A:
            flags |= FILEXFER_ATTR.ACMODTIME
            packet = packet.write_uint32(int(A.pop('atime', 0)))
            packet = packet.write_uint32(int(A.pop('mtime', 0)))

        for key in list(A):
            if not (type(key) is str and '@' in key or
                    type(key) is bytes and b'@' in key):
                A.pop(key)

        if use_extended and len(A) > 0:
            flags |= FILEXFER_ATTR.EXTENDED
            packet = packet.write_uint32(len(A))
            for key, val in A.items():
                tk = cls._ckstr(key).lstrip(b'@')
                tv = cls._ckstr(val)
                packet = packet.write_sftp_str(tk).write_sftp_str(tv)

        return packet.seek(0).write_uint32(flags).source

    @classmethod
    def _unpackattrs(cls, data, mark_end=False):
        """[private] Unpack an attributes structure from a packet payload,
        returning a dictionary of the corresponding values.  This is the
        inverse of ._packattrs().

        If mark_end is true, a special key "_end" is added to the result,
        giving the position in data at which the attribute block ended.
        """
        A = {}
        packet = sbitter(data).read_uint32()
        flags = packet.value
        if flags & FILEXFER_ATTR.SIZE:
            packet = packet.read_uint64().into(A, 'size')
        if flags & FILEXFER_ATTR.UIDGID:
            packet = packet.read_uint32().into(A, 'owner')
            packet = packet.read_uint32().into(A, 'group')
        if flags & FILEXFER_ATTR.PERMISSIONS:
            packet = packet.read_uint32().into(A, 'mode')
        if flags & FILEXFER_ATTR.ACMODTIME:
            packet = packet.read_uint32().into(A, 'atime')
            packet = packet.read_uint32().into(A, 'mtime')
        if flags & FILEXFER_ATTR.EXTENDED:
            packet = packet.read_uint32()
            count = packet.value
            for i in range(count):
                packet = packet.read_sftp_str()
                key = packet.value
                packet = packet.read_sftp_str().into(A, key)

        if mark_end:
            A['_end'] = packet.pos
        return A

    @classmethod
    def _cktype(cls, code, data, *expected):
        """[private] Packet type assertion.  The code must either be
        SSH_FXP_STATUS and the status must be SSH_FX_OK, or code must be one of
        the values in expected.

        If the result is SSH_FXP_STATUS and the result is an error, an
        sftp_status_errror exception is thrown giving the packet type, the
        error code, the error message, and the language tag.
        """
        p = sbitter(data)
        if code == FXP.STATUS:
            # Response format for SSH_FXP_STATUS
            # uint32    error code
            # string    error message
            # string    language tag
            #
            p = p.read_uint32()
            err_code = p.value
            if err_code != FX.OK:
                p = p.read_sftp_str()
                err_msg = p.value
                p = p.read_sftp_str()
                lang_tag = p.value

                raise sftp_status_error(err_code, err_msg, lang_tag)

        elif code not in expected:
            raise sftp_proto_error("unexpected response", code, expected)


class SFTP(sftp_client):
    """A wrapper for sftp_client that includes an interface to set up and tear
    down an SSH connection at the appropriate times.
    """

    def __init__(self, host, **kw):
        """See sshclient.SSH.__init__(...) for interpretation of arguments.

        Special keywords:
        chdir = v  -- After startup, do self.chdir(v).
        """
        kw['subsystem'] = 'sftp'
        self._chd = kw.pop('chdir', None)
        self._ssh = sshclient.SSH(host, **kw)
        super(SFTP, self).__init__(None, None)

    def __del__(self):
        self.close()

    def start(self):
        ssh = self._ssh.start()
        self.ifd = ssh.output_fd
        self.ofd = ssh.input_fd
        res = super(SFTP, self).start()
        if self._chd is not None:
            res.chdir(self._chd)
        return res

    def stop(self):
        super(SFTP, self).stop()
        return self._ssh.stop()


def checkopen(meth):
    """Verify that the file is open before applying a file method.  Raises
    ValueError if the file is closed.
    """

    def wrapper(self, *args, **kw):
        if self.handle is None:
            raise ValueError("I/O operation on closed file")
        return meth(self, *args, **kw)

    return functools.update_wrapper(wrapper, meth)


class sftp_entry(tuple):
    """Information on a directory entry."""

    def __new__(cls, dp, index, name, label, stat):
        return tuple.__new__(cls, (name, label, stat))

    def __init__(self, dp, index, name, label, stat):
        self.dir = dp
        self._index = index

    @property
    def name(self):
        return self[0]

    @property
    def label(self):
        return self[1]

    @property
    def stat(self):
        return self[2]

    @property
    def index(self):
        return self._index

    @property
    def path(self):
        return os.path.join(self.dir.path, self.name)

    @property
    def stat(self):
        return self.dir.client.lstat(self.path)


class sftp_thing(object):
    """Base class for file and directory wrappers."""

    def __init__(self, cli, handle, path=None):
        self.client = cli
        self.handle = handle
        self._path = path
        self._pres = False  # true if path has been looked up

    @property
    @checkopen
    def path(self):
        """The complete path of this entry on the server."""
        if self._path is not None and not self._pres:
            self._path = self.client.realpath(self._path)
            self._pres = True
        return self._path

    @property
    @checkopen
    def name(self):
        """The name of this entry."""
        path = self.path
        return path if path is None else os.path.basename(path)

    @property
    def closed(self):
        """True if the filehandle is closed."""
        return self.handle is None

    def close(self):
        """Release the filehandle back to the server."""
        if self.handle is not None:
            try:
                self.client._release(self.handle)
            except sftp_io_error:
                pass
            self.handle = None
            self.client = None

    def __repr__(self):
        return '#<%s handle=%r client=%x>' % (type(self).__name__, self.handle,
                                              id(self.client))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()


class sftp_file(sftp_thing):
    """Provides an interface to a file on an SFTP server that is similar to the
    built-in file object.  You will not usually construct instances of
    sftp_file directly, but will obtain them from the .open() and .create()
    methods of sftp_client.

    Instances of this class behave as a context manager that will close the
    file when it exits scope.
    """

    # Seek offset anchors, mirrored from os for convenience.
    SEEK_SET = os.SEEK_SET
    SEEK_CUR = os.SEEK_CUR
    SEEK_END = os.SEEK_END

    def __init__(self, cli, handle, path=None, flags=0):
        super(sftp_file, self).__init__(cli, handle, path)
        self._isapp = bool(flags & FXF.APPEND)
        self._pos = 0

    def __iter__(self):
        """Iterate over the lines of the file from the current position to the
        end of the file.

        During iteration of the file, the cursor is moved as each line is
        consumed, but changes to the cursor made outside the iterator between
        lines are ignored.
        """
        pos = self._pos
        cache = b''
        while True:
            pos, data, cache = self._readline(pos, cache)
            self._pos = pos
            if not data:
                break
            yield data

    def _read(self, vs, eof_ok=True):
        res = self.readv(vs)
        for pos, elt in enumerate(res):
            if type(elt) is bytes: pass
            elif elt.args[0] == FX.EOF:
                if eof_ok: res[pos] = b''
                else: raise EOFError
            else:
                raise elt

        return b''.join(res)

    def _ckcount(self, count):
        if count is not None and count < 0:
            raise ValueError("negative read count")

        size = self.stat['size']
        if count is None: return size - self._pos
        else: return min(count, size)

    def read(self, count=None):
        """Read the specified number of bytes at the current cursor position.
        If count is omitted, the rest of the file is read.  If the current
        position is at or after the total file size, an empty string is
        returned.
        """
        rc = self._ckcount(count)
        out = self._read(self._burst(self._pos, rc, self.client.MAX_READ_SIZE))
        self._pos += len(out)
        return out

    def read_at(self, offset, count, eof_ok=True):
        """Read the specified number of bytes at a specific offset.  Does not
        move the cursor.

        If eof_ok is True, reads outside the current file bounds will return an
        empty string; otherwise, EOFError is thrown.
        """
        rc = self._ckcount(count)
        return self._read(
            self._burst(offset, rc, self.client.MAX_READ_SIZE), eof_ok)

    def readline(self):
        """Read from the current position to the next available line break, and
        returns the resulting string, including the break.  Returns an empty
        string at EOF.  The cursor is moved to the next position after the end
        of the line returned.
        """
        end, data, _ = self._readline(self._pos)
        self._pos = end
        return data

    def _readline(self, start_pos, cache=b''):
        """[private] Read the next available line beginning at start_pos.
        Returns a tuple (end_pos, string, tail) giving the position of the next
        available byte, the text of the resulting line, and any leftover data
        that was read but not consumed in finding the line break.

        Does not move the cursor.

        If cache is set, it is taken to be a prefix of the contents of the file
        starting at start_pos.
        """
        pos = start_pos + len(cache)
        chunk_size = 128
        buf = [cache]
        while True:
            if b'\n' in buf[-1]:
                break

            try:
                buf.append(self.read_at(pos, chunk_size, eof_ok=False))
                pos += len(buf[-1])
            except EOFError:
                break

        pos -= len(buf[-1])
        buf[-1], eol, cache = buf[-1].partition(b'\n')
        pos += len(buf[-1]) + len(eol)
        buf.append(eol)
        return pos, b''.join(buf), cache

    @checkopen
    def seek(self, pos, anchor=SEEK_SET):
        """Move the cursor to a new position; as lseek(2).  The resulting
        position is returned.
        """
        if anchor == self.SEEK_SET: np = pos
        elif anchor == self.SEEK_CUR: np = self._pos + pos
        elif anchor == self.SEEK_END: np = self.stat['size'] + pos
        else:
            raise ValueError("invalid anchor")

        if np < 0: raise IndexError("seek target is negative")
        else:
            self._pos = np
            return np

    @property
    @checkopen
    def stat(self):
        """Get file stat from the remote server."""
        return self.client._getstat(self.handle, FXP.FSTAT)

    @checkopen
    def setstat(self, attrs):
        """Set file stats on the remote server."""
        return self.client._setstat(self.handle, FXP.FSETSTAT, attrs)

    @property
    @checkopen
    def statvfs(self):
        """[ext] Return VFS stat information for the filesystem containing this
        file.  See sftp_client.statvfs() for a description of the return value.
        """
        return self.client._unpackvfs(
            self.client._extreq("fstatvfs@openssh.com",
                                self.client._packstr(self.handle)))

    def tell(self):
        """Return the current file cursor position."""
        return self._pos

    @checkopen
    def truncate(self, pos=None):
        """Truncate the file at the specified position, or at the cursor if no
        position is given.  Does not move the cursor.
        """
        if pos is None: pos = self._pos
        if pos < self.stat['size']:
            self.setstat(dict(size=pos))

    def write(self, data):
        """Write the specified data at the current cursor position, or at
        end-of-file if the file is opened for appending.  Returns the number of
        bytes written.
        """
        if self._isapp:
            self.seek(0, self.SEEK_END)
        nw = self.writev([(self._pos, data)])
        self._pos += nw
        return nw

    def write_at(self, offset, data):
        """Write the specified data at a specific offset in the file.  Does not
        move the cursor.  Returns the number of bytes written.
        """
        return self.writev([(offset, data)])

    @checkopen
    def readv(self, vs):
        """Read a sequence of (offset, count) pairs and return a list of the
        resulting blocks in the same order as the corresponding request pairs.

        Block data is returned as byte strings; in case of error, the block
        data is replaced with an sftp_status_error object.
        """
        out = list([] for t in vs)
        rmap = {}
        size = self.stat['size']
        base = sbitter(b'').write_sftp_str(self.handle)

        # Queue up all the reads without waiting; we will then wait
        # for the reads to come back in
        for pos, (offset, count) in enumerate(vs):
            p = base.write_uint64(offset).write_uint32(count)
            r = self.client._getid()
            t = self.client.put_packet(FXP.READ, r, p.source)
            rmap[r] = (pos, t)

        def mfunc(t):
            return t.t_request_id in rmap

        # Wait for all the requests to return, for good or for ill.
        # In principle, they may complete in any order.

        while rmap:
            code, id, data = self.client.get_matching_packet(mfunc)

            pos, t = rmap[id]
            try:
                self.client._cktype(code, data, FXP.DATA)
                out[pos].append(sbitter(data).read_sftp_str().value)

                # If we didn't get a whole block (e.g., because we
                # requested something spanning more than one packet),
                # we will add a request for the remainder.
                offset, count = vs[pos]

                dlen = sum(len(s) for s in out[pos])
                if dlen < count and offset + count <= size:
                    offset += dlen
                    count -= dlen

                    p = base.write_uint64(offset).write_uint32(count)
                    r = self.client._getid()
                    t = self.client.put_packet(FXP.READ, r, p.source)
                    rmap[r] = (pos, t)

            except sftp_status_error as e:
                out[pos] = e

            rmap.pop(id)

        return list((b''.join(s) if isinstance(s, list) else s) for s in out)

    @checkopen
    def writev(self, vs):
        """Write a sequence of (offset, data) pairs and return the total number
        of bytes written, or throw sftp_status_error.

        More writes may be generated than the number of elements in vs, if the
        size of an individual write is too large.  The largest block that will
        be written in a single transaction is sftp_client.MAX_WRITE_SIZE bytes.
        """
        total = 0
        error = None
        wmap = {}
        base = sbitter(b'').write_sftp_str(self.handle)

        # Queue up all the writes without waiting; we will then wait
        # for the confirmations.
        for offset, data in vs:
            for lo, nc in self._burst(offset, len(data),
                                      self.client.MAX_WRITE_SIZE):
                db = lo - offset
                d = data[db:db + nc]
                p = base.write_uint64(lo).write_sftp_str(d)
                r = self.client._getid()
                t = self.client.put_packet(FXP.WRITE, r, p.source)
                wmap[r] = t, len(d)

        def mfunc(t):
            return t.t_request_id in wmap

        # Wait for all the requests to return, for good or for ill.
        # In principle, they may complete in any order.  Even if we
        # discover an error, we will wait for all of the transactions
        # to complete before complaining.

        while wmap:
            code, id, data = self.client.get_matching_packet(mfunc)
            t, dlen = wmap.pop(id)
            try:
                self.client._cktype(code, data)
                total += dlen
            except sftp_status_error as e:
                error = e

        if error is None:
            return total
        else:
            raise error

    @classmethod
    def _burst(cls, offset, count, size):
        """[private] Generate a list of separate contiguous (offset, count)
        regions that span the specified range with each range being no larger
        than size.
        """
        spans = []
        max = offset + count
        for lo in range(offset, max, size):
            hi = min(lo + size, max)
            spans.append((lo, hi - lo))
        return spans


class sftp_dir(sftp_thing):
    """Provides an interface to a directory as an iterable sequence.

    Usage:
     d = cli.opendir('/path/to/directory')
     first_entry = d[0]
     last_entry  = d[-1]
     num_entries = len(d)
     name, long, attrs = d[5]
    """

    def __init__(self, cli, handle, path=None):
        super(sftp_dir, self).__init__(cli, handle, path)
        self._items = []
        self._cpos = 0
        self._done = False

    @checkopen
    def _getpos(self, pos):
        while not self._done and pos >= len(self._items):
            p = sbitter(b'').write_sftp_str(self.handle)
            code, id, data = self.client.put_request(FXP.READDIR,
                                                     self.client._getid(),
                                                     p.source)

            try:
                self.client._cktype(code, data, FXP.NAME)
                nc = len(self._items)
                self._items.extend(
                    sftp_entry(self, nc + p, *v)
                    for p, v in enumerate(self.client._unpackname(data)))

            except sftp_status_error as e:
                if e.args[0] == FX.EOF: self._done = True
                else: raise

        return self._items[pos]

    def _getall(self):
        while not self._done:
            try:
                self._getpos(len(self._items))
            except IndexError:
                pass

    def __getitem__(self, itm):
        return self._getpos(itm)

    def __len__(self):
        self._getall()
        return len(self._items)

    def __iter__(self):
        pos = 0
        while True:
            try:
                yield self._getpos(pos)
            except IndexError:
                break
            finally:
                pos += 1

    @property
    @checkopen
    def stat(self):
        """Get directory stat from the remote server."""
        return self.client._getstat(self.path, FXP.LSTAT)

    @checkopen
    def setstat(self, attrs):
        """Set file stats on the remote server."""
        return self.client._setstat(self.path, FXP.SETSTAT, attrs)

    @property
    @checkopen
    def statvfs(self):
        """[ext] Return VFS stat information for the filesystem containing this
        file.
        """
        return self.client.statvfs(self.path)


__all__ = ("sftp_core", "sftp_client", "sftp_file", "sftp_dir")

# Here there be dragons
