"""Commands for the disposable runners: on the container, or in one of its namespaces."""

import subprocess


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr.strip()}")
    return result


def ip(*args):
    return run("ip", *args).stdout.strip()


def ns(name, *args, check=True):
    return run("ip", "netns", "exec", name, *args, check=check)
