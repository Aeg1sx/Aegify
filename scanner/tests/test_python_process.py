"""Check that process evidence follows the value passed to the standard library."""

import inspect
import subprocess
from textwrap import dedent, indent
from unittest.mock import patch

import pytest

from aegify.config import AegifyConfig
from aegify.models import CallSite, FileAST, Language
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_process import process_calls, process_input
from aegify.scanner.python_scope import PythonModules


def body(text):
    return (
        "import subprocess as sp\ndef check(raw, choice, options):\n"
        + indent(dedent(text).strip(), "    ")
        + "\n"
    )


def process(text):
    (fact,) = process_calls(body(text).encode()).values()
    return fact


@pytest.mark.parametrize(
    ("fn", "positional", "keywords", "source", "index"),
    [
        (
            subprocess.run,
            (["printf", "ready"],),
            {"shell": False},
            "sp.run(['printf', 'ready'], shell=False)",
            0,
        ),
        (
            subprocess.run,
            (),
            {"cwd": ".", "args": "printf ready", "shell": True},
            "sp.run(cwd='.', args='printf ready', shell=True)",
            1,
        ),
        (
            subprocess.Popen,
            (["printf", "ready"], -1, None, None, None, None, None, True, True),
            {},
            "sp.Popen(['printf', 'ready'], -1, None, None, None, None, None, True, True)",
            0,
        ),
        (
            subprocess.check_call,
            (["printf", "ready"],),
            {},
            "sp.check_call(['printf', 'ready'])",
            0,
        ),
        (
            subprocess.check_output,
            (),
            {"args": ["printf", "shell=True"]},
            "sp.check_output(args=['printf', 'shell=True'])",
            0,
        ),
        (
            subprocess.call,
            (),
            {"env": {"note": "shell=True"}, "args": ["printf", "ready"]},
            "sp.call(env={'note': 'shell=True'}, args=['printf', 'ready'])",
            1,
        ),
    ],
)
def test_call_binding_matches_cpython_before_process_creation(
    fn, positional, keywords, source, index
):
    signature = inspect.signature(subprocess.Popen._execute_child)
    observed = {}

    class HandoffError(Exception):
        pass

    def stop_before_launch(*args, **kwargs):
        observed.update(signature.bind(*args, **kwargs).arguments)
        raise HandoffError

    with (
        patch.object(
            subprocess.Popen, "_execute_child", autospec=True, side_effect=stop_before_launch
        ),
        pytest.raises(HandoffError),
    ):
        fn(*positional, **keywords)
    result = process(source)
    assert result.argument_index == index
    assert observed["args"] == (positional[0] if positional else keywords["args"])
    assert result.shell is observed["shell"]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("sp.run(args=raw, shell=choice)", None),
        ("sp.call(*raw)", None),
        ("sp.run(raw, **options)", None),
        ("sp.run(raw, shell=False, **options)", False),
        ("sp.run(['printf', 'shell = True'])", False),
        ("flag = True\nsp.run(raw, shell=flag)", True),
        ("flag = True\nif choice:\n    flag = False\nsp.run(raw, shell=flag)", None),
    ],
)
def test_unknown_and_rebound_options(command, expected):
    assert process(command).shell is expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ("['/bin/sh', '-c', raw, choice]", ["raw"]),
        ("('bash', '-lc', raw)", ["raw"]),
        ("['cmd.exe', '/C', 'echo', raw]", ["raw"]),
        ("['printf', '%s', raw]", []),
        ("['sh', '-c', 'printf ready', raw]", []),
        ("['/local/tools/sh', '-c', raw]", []),
    ],
)
def test_interpreter_roles(argv, expected):
    assert [p.expression for p in process(f"sp.run({argv})").command_parts] == expected


@pytest.mark.parametrize(
    "change",
    [
        "other = argv",
        "opaque(argv)",
        "argv.reverse()",
        "argv.pop()",
        "argv[0] = other",
        "for part in raw:\n    argv.append(part)",
        "argv += raw",
        "argv.append(*raw)",
        "argv.extend(raw)",
        "argv.append(argv)",
        "if opaque(argv):\n    argv.append(raw)",
    ],
)
def test_opaque_preceding_writes_keep_whole_argument_fallback(change):
    fact = process("argv = ['sh', '-c']\n" + change + "\nargv.append(raw)\nsp.run(argv)")
    assert fact.command_parts == [] and fact.argument_index == 0


def test_conditional_sequences_preserve_order_and_exits():
    fact = process("""
        argv = []
        if choice:
            argv.extend(['sh', '-c'])
        else:
            argv.extend(['bash', '-lc'])
        if False:
            argv.append(choice)
        if raw is None:
            argv.append(choice)
            return
        argv.append(raw)
        sp.run(argv)
    """)
    assert [(p.expression, p.line) for p in fact.command_parts] == [("raw", 13)]


def test_overrides_aliases_and_repository_modules(tmp_path):
    assert process("sp.run(['sh', '-c', raw], executable='/local/runner')").command_parts == []
    assert process("start = sp.run\nstart(raw)").api == "subprocess.run"
    assert process_calls(body("start = sp.run\nstart = choice\nstart(raw)").encode()) == {}
    path = tmp_path / "client.py"
    path.write_text(body("sp.run(raw, shell=True)"))
    file = ASTParser().parse_file(path)
    file.module_path = "client.py"
    (call,) = [c for c in file.calls if c.python_process_input]
    shadow = FileAST(
        file_path=str(tmp_path / "subprocess.py"),
        module_path="subprocess.py",
        language=Language.PYTHON,
    )
    assert process_input(call, file, PythonModules([file, shadow])) is None
    assert process_input(call, file, PythonModules([file])).shell is True


def test_older_snapshots_bind_real_flags():
    file = FileAST(file_path="client.py", language=Language.PYTHON)
    modules = PythonModules([file])
    call = CallSite(
        file_path="client.py",
        line=1,
        column=0,
        callee="run",
        receiver="subprocess",
        arguments=["cwd='.'", "args=raw", "shell=True"],
    )
    assert process_input(call, file, modules).argument_index == 1
    assert process_input(call, file, modules).shell is True
    call.arguments = ["['printf', 'shell=True']"]
    assert process_input(call, file, modules).shell is False


def test_saved_value_has_an_actual_source_write_and_process_trace(tmp_path):
    path = tmp_path / "receipt.py"
    path.write_text(
        "import subprocess\nfrom flask import request\ndef record():\n"
        "    title = request.args.get('title', '')\n    argv = ['sh', '-c']\n"
        "    argv.append(title)\n    title = 'printf ready'\n    return subprocess.run(argv)\n"
    )
    config = AegifyConfig()
    config.llm.enabled = False
    scan = ScanEngine(config=config).scan_files(tmp_path, [path])
    (finding,) = [f for f in scan.findings if f.rule_id == "AEG-CMD-001"]
    assert finding.line_start == 8
    assert finding.taint_flow.source.line == 4
    assert (6, "command-argument") in [
        (step.line, step.propagation_type) for step in finding.taint_flow.path
    ]
