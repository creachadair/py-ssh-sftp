##
## Name:     bitter.py
## Purpose:  Encoding and parsing tools for binary packets.
##

import struct

# {{ class bitter

class bitter (object):
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
    def __init__(self, source, pos = 0, value = None):
        """Source may be any indexable sequence type.
        """
        self._src = source
        self._pos = slice(pos).indices(len(source))[1]
        self._val = value

    @property
    def pos(self): return self._pos
    @property
    def source(self): return self._src
    @property
    def value(self): return self._val
    @property
    def length(self): return len(self._src)

    def seek(self, pos):
        """Seek to the specified absolute position, returning a bitter.
        Use None to seek to the end.
        """
        if pos is None: pos = self.length
        if pos == self.pos: return self
        else: return type(self)(self.source, pos, self.value)

    def move(self, offset):
        """Seek relative to the current position, returning a bitter.
        """
        if offset == 0: return self
        else: return type(self)(self.source, self.pos + offset, self.value)

    def set(self, value):
        """Return a bitter with its value set."""
        return type(self)(self.source, self.pos, value)

    def setlength(self):
        """Return a bitter with its value set to its source length."""
        return type(self)(self.source, self.pos, self.length)

    def usevalue(self, func, *args, **kw):
        """Call func with the value, then return the bitter."""
        func(self.value, *args, **kw) ; return self

    def usesource(self, func, *args, **kw):
        """Call func with the source, then return the bitter."""
        func(self.source, *args, **kw) ; return self

    def update(self, func, *args, **kw):
        """Update the value by applying func to the current value."""
        return type(self)(self.source, self.pos, func(self.value, *args, **kw))

    def into(self, d, key):
        """Store the value into a dictionary under the given key."""
        d[key] = self.value
        return self

    def as_key(self, d, val = None):
        """Store the value as a key in a dictionary with the given value."""
        d[self.value] = val
        return self

    def __len__(self): return self.length

    def __repr__(self):
        return '#<%s @%d src[%d]=%r%s%s>' % (
            type(self).__name__, self.pos, len(self),
            self.source[:24], '+' if len(self) > 24 else '',
            '' if self.value is None else 'v')

    def read(self, nc = None):
        """Read up to nc elements at the current position into value.
        Set None to use the value.
        """
        if nc is None: nc = self.value or 0
        d = self.source[self.pos : self.pos + nc]
        return type(self)(self.source, self.pos + len(d), d)

    def readn(self, nc = None):
        """Read exactl nc elements at the current position into value.
        Set None to use the value.
        """
        if nc is None: nc = self.value or 0
        d = self.source[self.pos : self.pos + nc]
        if len(d) != nc: raise ValueError("expected %d elements" % nc)
        return type(self)(self.source, self.pos + len(d), d)

    def readuntil(self, func, include = False):
        """Read input elements, up to the first e for which func(e) is
        true, into value.  If include is true, the trigger element is
        included in the value; otherwise not.
        """
        inc = int(bool(include))
        for i in range(self.pos, self.length):
            if func(self.source[i]):
                return type(self)(self.source, i + inc, self.source[self.pos:i+inc])
        else:
            raise ValueError("unexpected end of input")

    def readwhile(self, func):
        """Read input elements up to and including the first e for
        which func(e) is false, into value.
        """
        i = self.pos
        while i < self.length:
            if func(self.source[i]): i += 1
            else: break
        return type(self)(self.source, i, self.source[self.pos:i])

    def splice(self, nc):
        """Splice nc elements out af the current position into value.
        Set None to use the value.
        """
        if nc is None: nc = self.value
        end = self.pos + nc
        d = self.source[self.pos : end]
        v = self.source[:self.pos] + self.source[end:]
        return type(self)(v, self.pos, d)

    def insert(self, v = None):
        """Insert the elements of v in at the current position.  Set
        None to insert the value.
        """
        if v is None: v = self.value
        d = self.source[:self.pos] + v + self.source[self.pos:]
        return type(self)(d, self.pos + len(v), self.value)

    def write(self, v = None):
        """Write elements of v at the current position.  Set None to
        write the value.
        """
        if v is None: v = self.value
        d = self.source[:self.pos] + v
        np = len(d)
        return type(self)(d + self.source[np:], np, self.value)

    def trunc(self, pos = None):
        """Truncate at the specified offset.  Use None to truncate at
        the current position.
        """
        if pos is None: pos = self.pos
        if pos >= self.length: return self
        else: return type(self)(self.source[:pos], self.pos, self.value)

# }}

# {{ class pbitter

class pbitter (bitter):
    """Extends the bitter interface with encoding and decoding rules
    for a platform-neutral binary encoding.

    Each object begins with a single-byte prefix encoding its type.
    The type determines the format of the following data.  Here, the
    type prefixes are shown using their ASCII equivalents:

    A num obj[num]    -- ordered mutable array of objects.
    B len data[len]   -- opaque binary data.
    D num kv[num]     -- key/value dictionary.
      where kv is
      K obj    -- key object
      V obj    -- value object
    F len data[len]   -- floating-point as ASCII text.
    N uint            -- negative integer.
    P uint            -- non-negative integer.
    S num obj[num]    -- unordered set of objects (no duplicates).
    T num obj[num]    -- ordered immutable array (tuple) of objects.
    U len data[len]   -- unicode string in UTF-8 encoding.
    ? uint            -- boolean value: 1 = true, 0 = false.
    $                 -- the nil (unit) value (e.g., None).

    The uint encoding is a base-128 encoding of a non-negative integer
    value into a sequence of 8-bit bytes in network (big-endian)
    order.  The high-order bit of each byte is set, except for the
    last in the sequence, which marks the end of the value.

    All length (len) and count (num) fields are stored using the uint
    encoding.
    """
    def pack(self, fmt, *args):
        """Equivalent to self.write(struct.pack(fmt, *args)).
        """
        return self.write(struct.pack(fmt, *args))

    def unpack(self, fmt):
        """Unpack a format from the struct module into the value.
        """
        return self.readn(struct.calcsize(fmt)).update(
            lambda v: struct.unpack(fmt, v))

    def readcheck(self, v):
        """Read a fixed sequence expected to equal v.  Throws
        ValueError if the value does not match.
        """
        c = self.read(len(v))
        if c.value != v: raise ValueError("expected %r" % v)
        return c

    def eofcheck(self):
        """Throws ValueError if the current position is not at
        the end of the input.
        """
        if self.pos < self.length:
            raise ValueError("expected EOF")
        return self

    def write_byte(self, b):
        """Write a single byte."""
        return self.write(bytes([b]))

    def write_uint(self, z):
        """Write an unsigned integer value."""
        if z < 0: raise ValueError(z)
        q = bytearray()
        while True:
            z, r = z // 128, z % 128
            q.append(r + 128)
            if z == 0: break

        q[0] -= 128; q.reverse()
        return self.write(bytes(q))

    def read_uint(self):
        """Read an unsigned integer value."""
        c = self.readuntil(lambda v: v < 128, True)
        v = 0
        for b in c.value:
            v = (v * 128) + (b % 128)
        return c.set(v)

    def write_str(self, s):
        """Write a Unicode string encoded as UTF-8."""
        b = s.encode('utf8')
        return self.write_uint(len(b)).write(b)

    def read_str(self):
        """Read a Unicode string encoded as UTF-8."""
        return self.read_uint().read().update(
            lambda v: v.decode('utf8'))

    def write_float(self, f):
        """Write a floating-point value."""
        b = str(f).encode('ascii')
        return self.write_uint(len(b)).write(b)

    def read_float(self):
        """Read a floating-point value."""
        return self.read_uint().read().update(float)

    def write_obj(self, obj):
        """Write a tagged object."""
        if isinstance(obj, bool):
            return self.write(b'?').write_uint(int(obj))
        elif isinstance(obj, int):
            return self.write(b'N' if obj < 0 else b'P') \
                   .write_uint(abs(obj))
        elif isinstance(obj, (bytes, bytearray)):
            return self.write(b'B').write_uint(len(obj)).write(obj)
        elif isinstance(obj, str):
            return self.write(b'U').write_str(obj)
        elif isinstance(obj, float):
            return self.write(b'F').write_float(obj)
        elif isinstance(obj, list):
            return self.write(b'A').write_array(obj)
        elif isinstance(obj, tuple):
            return self.write(b'T').write_array(obj)
        elif isinstance(obj, dict):
            return self.write(b'D').write_dict(obj)
        elif isinstance(obj, set):
            return self.write(b'S').write_array(obj)
        elif obj is None:
            return self.write(b'$')
        else:
            raise ValueError("unwritable object %r" % obj)

    def write_array(self, seq):
        """Write a sequence of objects."""
        c = self.write_uint(len(seq))
        for obj in seq:
            c = c.write_obj(obj)
        return c

    def write_dict(self, obj):
        """Write a dictionary of key/value pairs."""
        c = self.write_uint(len(obj))
        for key, val in obj.items():
            c = c.write(b'K').write_obj(key)
            c = c.write(b'V').write_obj(val)
        return c

    def read_obj(self):
        """Read a tagged object."""
        c = self.read(1)
        if c.value == b'N':
            return c.read_uint().update(lambda v: -v)
        elif c.value == b'P':
            return c.read_uint()
        elif c.value == b'B':
            return c.read_uint().read()
        elif c.value == b'U':
            return c.read_str()
        elif c.value == b'F':
            return c.read_float()
        elif c.value == b'A':
            return c.read_array()
        elif c.value == b'T':
            return c.read_array().update(tuple)
        elif c.value == b'D':
            return c.read_dict()
        elif c.value == b'S':
            return c.read_array().update(set)
        elif c.value == b'?':
            return c.read_uint().update(bool)
        elif c.value == b'$':
            return c.set(None)
        else:
            raise ValueError("unknown type key %r" % c.value)

    def read_array(self):
        """Read an array of objects."""
        c = self.read_uint()
        out = [None] * c.value
        for i in range(len(out)):
            c = c.read_obj()
            out[i] = c.value
        return c.set(out)

    def read_dict(self):
        """Read a dictionary of key/value pairs."""
        c = self.read_uint()
        out = {}
        for i in range(c.value):
            c = c.readcheck(b'K').read_obj()
            k = c.value
            c = c.readcheck(b'V').read_obj()
            v = c.value
            out[k] = v
        return c.set(out)

# }}

__all__ = ('bitter', 'pbitter')

# Here there be dragons
