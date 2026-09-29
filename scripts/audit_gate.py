"""Hosted built-interpreter ABI regression only; not a general launch guard."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


class AuditDenied(BaseException):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    if (os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('ImageOS') != 'win22'
            or Path(sys.executable).resolve() != package / 'python.exe'
            or sys.version_info[:3] != (3, 14, 7) or struct.calcsize('P') != 8
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or 'site' in sys.modules):
        raise RuntimeError('Gate is restricted to the packaged hosted Release x64 interpreter')
    paths = {Path(value).resolve() for value in sys.path}
    if not {package / 'Lib', package / 'DLLs'}.issubset(paths) or Path(sys.prefix) != package:
        raise RuntimeError('Normal app-local Lib/DLLs layout required')
    for path in package.rglob('*'):
        if (path.name.lower().endswith('._pth') or path.suffix.lower() in {'.pyc', '.pyo', '.zip'}
                or path.name.lower() in {'__pycache__', 'site-packages', 'pip', 'ensurepip'}):
            raise RuntimeError('Forbidden runtime layout member')
    if any(name in sys.modules for name in ('site', 'sitecustomize', 'usercustomize', 'pip')):
        raise RuntimeError('Unexpected site/pip initialization')
    for value in sys.path:
        if not Path(value).resolve().is_relative_to(package):
            raise RuntimeError('Interpreter escaped its app-local library path')
    if not sys._is_gil_enabled() or (hasattr(sys, '_jit') and sys._jit.is_available()):
        raise RuntimeError('Unexpected GIL/JIT configuration')
    binding = json.loads((package / 'build-binding.json').read_bytes())
    for name in ['python.exe', 'python314.dll']:
        if hashlib.sha256((package / name).read_bytes()).hexdigest() != binding[name]:
            raise RuntimeError('Built executable binding mismatch')
    # Required native imports; no SQLite connection or filesystem-backed database.
    modules = {}
    for name in ['_bz2', '_hashlib', '_lzma', '_sqlite3', '_uuid', '_zstd', 'unicodedata']:
        module = importlib.import_module(name)
        file = Path(module.__file__).resolve(strict=True)
        if not file.is_relative_to(package):
            raise RuntimeError('Extension escaped package')
        modules[name] = {'path': file.relative_to(package).as_posix(),
                         'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}
    import _decimal
    import _sqlite3
    import _ssl
    import _zstd
    import unicodedata
    import zlib
    versions = {'python': sys.version, 'openssl': _ssl.OPENSSL_VERSION,
                'sqlite': _sqlite3.sqlite_version, 'zstd': _zstd.zstd_version,
                'mpdecimal': _decimal.__libmpdec_version__, 'unicode': unicodedata.unidata_version,
                'zlib': zlib.ZLIB_RUNTIME_VERSION,
                'bz2': '1.0.8 (pinned source; no runtime version API)',
                'lzma': '5.2.5 (pinned source; no runtime version API)',
                'uuid': 'Windows RPC implementation (no library version API)'}
    import _winapi
    sentinel = package / 'absent-audit-sentinel' / 'never-created.exe'
    if not sentinel.is_absolute() or sentinel.exists() or sentinel.parent.exists():
        raise RuntimeError('The absolute non-executable sentinel must be absent')
    application = str(sentinel)
    cwd = str(package)
    cases = [
        ('A1-ascii', 'ascii', cwd, AuditDenied),
        ('A2-spaces', 'alpha beta gamma', cwd, AuditDenied),
        ('A3-quote-trailing-backslash', subprocess.list2cmdline(['a"b', 'space tail\\']), cwd, AuditDenied),
        ('A4-unicode', '\u00e9\u6f22\U0001f642', cwd, AuditDenied),
        ('A5-4096-ascii', 'A' * 4096, cwd, AuditDenied),
        ('A6-command-none', None, cwd, AuditDenied),
        ('A7-cwd-none', 'ascii', None, AuditDenied),
        ('A8-runtimeerror', 'ascii', cwd, RuntimeError),
    ]
    events = []
    denial = AuditDenied('unconditional audit denial')

    def audit(event, arguments):
        if event == '_winapi.CreateProcess':
            events.append(arguments)
            raise denial  # unconditional: never authorizes OS process creation

    sys.addaudithook(audit)
    results = []
    for label, command, directory, exception_class in cases:
        events.clear()
        denial = exception_class('unconditional audit denial')
        caught = None
        try:
            _winapi.CreateProcess(application, command, None, None, False, 0,
                                  None, directory, subprocess.STARTUPINFO())
        except BaseException as exc:
            caught = exc
        else:
            raise AssertionError('Unexpected process handles returned; abort without retry')
        if caught is not denial or type(caught) is not exception_class:
            raise AssertionError(f'{label}: designated audit exception was not propagated')
        if len(events) != 1 or len(events[0]) != 3:
            raise AssertionError(f'{label}: require exactly one three-argument audit event')
        actual = events[0]
        expected = (application, command, directory)
        if actual != expected or actual[1] is not command:
            raise AssertionError(f'{label}: value/command-object identity mismatch')
        for value, original in zip(actual, expected):
            if (original is None and value is not None) or (original is not None and type(value) is not str):
                raise AssertionError(f'{label}: audit argument type mismatch')
        results.append({'case': label, 'events': 1, 'exact_values': True,
                        'command_identity': True, 'designated_exception': exception_class.__name__,
                        'process_handles_returned': False})
    if len(results) != 8:
        raise AssertionError('Incomplete gate')
    args.report.write_text(json.dumps({'scope': 'runtime ABI only, not launch-guard acceptance',
                                      'versions': versions, 'extensions': modules,
                                      'sys_path': [str(p.relative_to(package)) for p in sorted(paths)],
                                      'site_initialized': False, 'jit_available': sys._jit.is_available(),
                                      'cases': results, 'passed': True}, indent=2) + '\n', encoding='utf-8')
    print('PASS: A1-A8, required extensions, exact audit denial; no handles returned')


if __name__ == '__main__':
    main()
