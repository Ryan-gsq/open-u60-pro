"""Network namespace helpers for the isolated Linux acceptance scripts."""

import ctypes
import os
import threading

_LIBC = ctypes.CDLL(None, use_errno=True)


def enter(ns):
    """Move this thread into network namespace `ns`."""
    fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    try:
        if _LIBC.setns(fd, 0x40000000) != 0:  # CLONE_NEWNET
            raise OSError(ctypes.get_errno(), "setns")
    finally:
        os.close(fd)


def in_ns(ns, target, *args):
    """Run `target(*args)` in a thread in network namespace `ns`."""
    result = {}

    def run():
        enter(ns)
        try:
            result["value"] = target(*args)
        except Exception as e:  # noqa: BLE001 - reported as the result
            result["value"] = f"error: {e}"

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    return result.get("value")
