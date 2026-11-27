"""Source-only fixtures for import identity and the subprocess option binder."""

import subprocess as processes
from subprocess import run as launch

from flask import request


def imported_alias():
    title = request.args.get("title", "")
    return launch(cwd=".", args=title, shell=True)


def local_alias():
    title = request.args.get("title", "")
    start = processes.check_output
    return start(args=title, shell=True)


def fixed_command():
    return launch("printf ready", shell=True)


def text_in_environment():
    return processes.run(["printf", "ready"], env={"note": "shell=True"})


def text_in_diagnostic_output():
    import subprocess

    return subprocess.run(["printf", "shell = True"])
