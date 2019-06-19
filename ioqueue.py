##
## Name:     ioqueue.py
## Purpose:  Multi-threaded work queue.
##
## Copyright (c) 2009 Michael J. Fromberger, All Rights Reserved.
##

import threading, sys

if sys.version_info[0] == 3:

    def TIMEOUT(v):
        return v
else:
    _mainthread = threading.current_thread()

    def TIMEOUT(v):
        # Interpret a timeout value.  Ordinarily, None means no timeout, but if
        # we sleep the main thread unconditionally, signal handlers will not
        # get to run.  As far as I can tell, this is a limitation of cPython.
        #
        # So: Here, we patch the timeout to be a very large (but not infinite)
        # value when the main thread asks for no timeout.
        if v is None and threading.current_thread() is _mainthread:
            return 2**31
        else:
            return v


class task_missing(KeyError):
    "No such task exists."


class task_not_owner(KeyError):
    "You are not the owner of that task."


class task(object):

    def __init__(self, id, tag, attrs):
        self.id = id
        self.tag = tag
        self.attrs = attrs
        self.status = None
        self.done = False
        self._waitx = True
        self._tcond = threading.Condition(threading.Lock())

    def __getattr__(self, attr):
        if attr.startswith('t_'):
            try:
                return self.attrs[attr[2:]]
            except KeyError:
                pass
        raise AttributeError(attr)

    @property
    def detached(self):
        with self._tcond:
            return not self._waitx

    @detached.setter
    def detached(self, value):
        with self._tcond:
            self._waitx = not bool(value)

    def join(self, timeout=None):
        with self._tcond:
            if not self.done:
                self._tcond.wait(TIMEOUT(timeout))
                if not self.done:
                    raise ValueError("task cancelled")
            return self.status

    def cancel(self):
        with self._tcond:
            self._tcond.notify_all()

    def finish(self, status):
        with self._tcond:
            if self.done:
                raise ValueError("task is already done")
            else:
                self.done = True
                self.status = status
                self._tcond.notify_all()

    def __repr__(self):
        return '#<%s id=%s tag=%r>' % (type(self).__name__, self.id, self.tag)


class ioqueue(object):
    """Simple producer/consumer queue.  Similar to the "queue" module,
    but gives the consumer access to tasks that may not be at the head
    of the queue, and allows a producer to push a task at the head of
    the queue.
    """

    def __init__(self, **opts):
        """Keyword options understood:

        detach_tasks -- if true, detach all new tasks by default.
        """
        self._tasks = {}  # unclaimed tasks; id -> rid, task
        self._busy = {}  # tasks in progress; id -> rid, wid, task
        self._detch = bool(opts.pop('detach_tasks', False))

        # rid -- thread ID that created the task
        # wid -- thread ID that is servicing the task

        # Protocol: Code wishing to read or write the above members
        # must hold this condition variable.

        self._tcond = threading.Condition(threading.RLock())

    def flush(self):
        """Cancel all pending tasks and empty the queue."""
        with self._tcond:
            # Cancel all unclaimed tasks.  We must cancel these as
            # someone might have immediately waited on them before
            # they were claimed.
            for id in list(self._tasks):
                rid, t = self._tasks.pop(id)
                t.cancel()

            # Cancel all pending tasks.
            for id in list(self._busy):
                rid, wid, t = self._busy.pop(id)
                t.cancel()

            # Rudely wake up anybody waiting for a queue change.
            self._tcond.notify_all()

    # --- Producer interface -------------------------------------------

    def _addid(self, id, tag, attrs):
        with self._tcond:
            t = task(id, tag, attrs)
            if self._detch: t.detached = True
            rid = threading.current_thread().ident

            self._tasks[id] = rid, t
            self._tcond.notify_all()
            return id

    def _findid(self, id, choose):
        with self._tcond:
            for i in self._tasks:
                id = choose(id, i)
            for i in self._busy:
                id = choose(id, i)
            return id

    def add_task(self, tag, **attrs):
        """Add a new task to the tail of the queue and return a task ID.
        """
        with self._tcond:
            id = self._findid(0, max) + 1
            return self._addid(id, tag, attrs)

    def detach_task(self, id):
        """Detach a task so that it will not be retained once complete.
        Returns the task ID so the operation can be chained.
        """
        with self._tcond:
            task = self._tasks.get(id)[1] or self._busy[id][2]
            task.detached = True
            if task.done:
                self._busy.pop(id)
            return id

    def push_task(self, tag, **attrs):
        """Add a new task to the head of the queue and block until it
        is complete, returning the status.

        Pushed tasks are always joinable, even if the default is to
        detach new tasks.
        """
        with self._tcond:
            id = self._findid(1, min) - 1
            self._addid(id, tag, attrs)
            rid, t = self._tasks[id]
            t.detached = False

        return self.join_task(t.id)

    def cancel_task(self, id):
        """Cancel a scheduled task and remove it from the queue.
        """
        with self._tcond:
            rid, t = self._tasks[id]

            if rid != threading.current_thread().ident:
                raise task_not_owner("task does not belong to you")

            self._tasks.pop(id)

    def cancel_all(self):
        """Cancel all tasks scheduled by this thread and remove them
        from the queue.  Returns a set of the task ID's removed.
        """
        with self._tcond:
            me = threading.current_thread().ident

            kill = set(id for id, (rid, t) in self._tasks.items() if rid == me)

            for id in kill:
                self._tasks.pop(id)

            return kill

    def join_task(self, id, timeout=None):
        """Block until the specified task is complete, and return its
        status.
        """
        with self._tcond:
            if id in self._tasks:
                rid, t = self._tasks[id]
            else:
                rid, wid, t = self._busy[id]

        res = t.join(timeout)

        # We can get rid of a task once it is complete and the
        # original thread that requested it has joined it.
        if t.done and rid == threading.current_thread().ident:
            with self._tcond:
                self._busy.pop(id, None)

        return res

    def purge_done(self):
        """Purge any completed tasks that were scheduled by this
        thread, discarding their status.  Does not block.
        """
        with self._tcond:
            me = threading.current_thread().ident
            kill = set()

            for id in self._busy:
                rid, wid, t = self._busy[id]

                if rid == me and t.done:
                    kill.add(id)

            for id in kill:
                self._busy.pop(id)

    # --- Consumer interface -------------------------------------------

    def _markbusy(self, id):
        rid, t = self._tasks.pop(id)
        self._busy[id] = rid, threading.current_thread().ident, t
        return t

    def next_task(self, timeout=None):
        """Remove and return the head of the queue.  If timeout is
        None, blocks until a task is available; otherwise throws
        KeyError if no task is found within the timeout.
        """
        return self.next_matching(lambda t: True, timeout)

    def task_done(self, task, status):
        """Mark a task as complete, and set its status.
        """
        with self._tcond:
            rid, wid, t = self._busy[task.id]

            if wid != threading.current_thread().ident:
                raise task_not_owner("task does not belong to you")
            elif t.detached:
                self._busy.pop(task.id)

            t.finish(status)

    def release_task(self, task):
        """Return a task to its original position in the queue,
        without marking it as complete.
        """
        with self._tcond:
            rid, wid, t = self._busy[task.id]

            if wid != threading.current_thread().ident:
                raise task_not_owner("task does not belong to you")

            self._busy.pop(task.id)
            self._tasks[task.id] = rid, task

    def next_matching(self, matching, timeout=None):
        """Remove and return the next task t for which matching(t) is
        true.  If timeout is None, blocks until a matching task is
        available, otherwise throws KeyError if no matching task is
        found within the timeout.
        """
        with self._tcond:
            first = True
            while True:
                for id in sorted(self._tasks):
                    rid, t = self._tasks[id]
                    if matching(t):
                        return self._markbusy(id)

                if first:
                    self._tcond.wait(TIMEOUT(timeout))
                    first = True if timeout is None else False
                else:
                    raise task_missing("no tasks")

    def all_matching(self, matching, timeout=None):
        """As .next_matching(), but returns all matching tasks in a
        list ordered by task ID.  Returns an empty list if no tasks
        were found within the timeout.
        """
        with self._tcond:
            found = []
            first = True
            while True:
                for id in sorted(self._tasks):
                    rid, t = self._tasks[id]
                    if matching(t):
                        found.append(self._markbusy(id))

                if first and not found:
                    self._tcond.wait(TIMEOUT(timeout))
                    first = True if timeout is None else False
                else:
                    return found


__all__ = ("ioqueue", "task")

# Here there be dragons
