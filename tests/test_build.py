"""Only fixture/static tests. Never import or invoke the runtime audit gate."""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import buildlib

SOURCE = None


class PatchTests(unittest.TestCase):
    def test_exact_one_byte(self):
        result = buildlib.patch_bytes(SOURCE)
        self.assertEqual(hashlib.sha256(result).hexdigest(), buildlib.AFTER)
        changes = [(a, b) for a, b in zip(SOURCE, result) if a != b]
        self.assertEqual(changes, [(ord('u'), ord('O'))])
        self.assertEqual(len(SOURCE), len(result))

    def test_changed_base_rejected(self):
        with self.assertRaises(ValueError):
            buildlib.patch_bytes(SOURCE + b'\n')

    def test_already_fixed_rejected(self):
        fixed = SOURCE.replace(b'PySys_Audit("_winapi.CreateProcess", "uuu"',
                               b'PySys_Audit("_winapi.CreateProcess", "uOu"')
        with self.assertRaises(ValueError):
            buildlib.patch_bytes(fixed)

    def test_missing_base_rejected(self):
        with self.assertRaises(ValueError):
            buildlib.patch_bytes(b'')


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEMP)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def zip(self, entries):
        archive = self.root / 'fixture.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for name, content in entries:
                z.writestr(name, content)
        return archive

    def test_safe_members(self):
        self.assertEqual(str(buildlib.safe_member('root/Lib/a.py', 'root')), 'Lib/a.py')
        self.assertIsNone(buildlib.safe_member('root/', 'root'))

    def test_unsafe_members_rejected(self):
        for name in ['../x', '/x', 'C:/x', 'a\\b', 'a//b', 'a/./b', 'a/../b',
                     'a/x:stream', 'a/NUL.txt', 'a/COM1', 'a/LPT¹', 'a/file.', 'a/file ',
                     'a/\x00x', 'a/<x', 'a/?x', 'a/*', 'a/"x']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                buildlib.safe_member(name)

    def test_wrong_root_rejected(self):
        with self.assertRaises(ValueError):
            buildlib.safe_member('other/file', 'expected')

    def test_zip_extract_positive(self):
        archive = self.zip([('root/a.txt', b'a'), ('root/sub/b.txt', b'b')])
        destination = self.root / 'output'
        buildlib.extract_archive(archive, destination, 'root')
        self.assertEqual(buildlib.inventory(destination), {'a.txt': buildlib.digest(b'a'),
                                                        'sub/b.txt': buildlib.digest(b'b')})

    def test_preflight_prevents_partial_extraction(self):
        archive = self.zip([('root/good', b'a'), ('root/../escape', b'b')])
        destination = self.root / 'output'
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, destination, 'root')
        self.assertFalse(destination.exists())

    def test_zip_case_collision(self):
        archive = self.zip([('root/A', b'a'), ('root/a', b'b')])
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, self.root / 'output', 'root')

    def test_zip_symlink(self):
        member = zipfile.ZipInfo('root/link')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self.zip([(member, b'../outside')])
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, self.root / 'output', 'root')

    def test_pinned_unused_link_omission(self):
        member = zipfile.ZipInfo('root/tests/link')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self.zip([(member, b'zstd'), ('root/kept.c', b'code')])
        destination = self.root / 'out'
        buildlib.extract_archive(archive, destination, 'root',
                                 omit_links={'tests/link': buildlib.digest(b'zstd')})
        self.assertEqual(buildlib.inventory(destination), {'kept.c': buildlib.digest(b'code')})
        self.assertFalse((destination / 'tests/link').exists())

    def test_pinned_link_omission_rejects_drift(self):
        member = zipfile.ZipInfo('root/tests/link')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self.zip([(member, b'changed')])
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, self.root / 'out', 'root',
                                     omit_links={'tests/link': buildlib.digest(b'zstd')})
        self.assertFalse((self.root / 'out').exists())

    def test_pinned_link_omission_requires_exact_type_and_presence(self):
        archive = self.zip([('root/tests/link', b'zstd')])
        for name in ['tests/link', 'absent']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                buildlib.extract_archive(archive, self.root / 'out', 'root',
                                         omit_links={name: buildlib.digest(b'zstd')})
        self.assertFalse((self.root / 'out').exists())

    def test_directory_spelling_does_not_hide_symlink(self):
        member = zipfile.ZipInfo('root/link/')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self.zip([(member, b'../outside')])
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, self.root / 'out', 'root')
        self.assertFalse((self.root / 'out').exists())

    def test_tar_extract_and_mtime(self):
        archive = self.root / 'fixture.tar.xz'
        with tarfile.open(archive, 'w:xz') as t:
            member = tarfile.TarInfo('root/data'); member.size = 3; member.mtime = 1000000000
            t.addfile(member, io.BytesIO(b'abc'))
        destination = self.root / 'output'
        buildlib.extract_archive(archive, destination, 'root')
        self.assertEqual((destination / 'data').read_bytes(), b'abc')
        self.assertEqual(int((destination / 'data').stat().st_mtime), 1000000000)

    def test_tar_special_entries(self):
        for index, kind in enumerate([tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                                      tarfile.CHRTYPE, tarfile.BLKTYPE]):
            archive = self.root / f'fixture{index}.tar.xz'
            with tarfile.open(archive, 'w:xz') as t:
                member = tarfile.TarInfo('root/link'); member.type = kind; member.linkname = '../outside'
                t.addfile(member)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                buildlib.extract_archive(archive, self.root / f'out{index}', 'root')

    def test_existing_destination_rejected(self):
        archive = self.zip([('root/a', b'a')])
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, self.root, 'root')

    def test_wheel_hook_rejected(self):
        archive = self.zip([('package/a.py', b''), ('hook.pth', b'import os')])
        with self.assertRaises(ValueError):
            buildlib.extract_archive(archive, self.root / 'out', wheel=True)
        self.assertFalse((self.root / 'out').exists())

    def test_expansion_bound(self):
        with mock.patch.object(buildlib, 'MAX_EXPANDED', 2):
            archive = self.zip([('root/a', b'abc')])
            with self.assertRaises(ValueError):
                buildlib.extract_archive(archive, self.root / 'out', 'root')


class IntegrityTests(unittest.TestCase):
    def test_hash_positive(self):
        self.assertEqual(buildlib.checked_hash(b'abc', hashlib.sha256(b'abc').hexdigest()), b'abc')

    def test_malformed_and_wrong_hashes(self):
        for token in ['0' * 64, 'A' * 64, 'a' * 63, ' a' * 32, 'a' * 64 + '\n']:
            with self.subTest(token=token), self.assertRaises(ValueError):
                buildlib.checked_hash(b'abc', token)

    def test_bad_hash_rejected_before_network(self):
        with mock.patch.object(buildlib.urllib.request, 'urlopen') as fetch:
            with self.assertRaises(ValueError):
                buildlib.download('https://www.python.org/file', 'bad', Path('unused'))
            fetch.assert_not_called()

    def test_bad_origin_rejected_before_network(self):
        with mock.patch.object(buildlib.urllib.request, 'urlopen') as fetch:
            with self.assertRaises(ValueError):
                buildlib.download('http://www.python.org/file', '0' * 64, Path('unused'))
            fetch.assert_not_called()

    def test_hosted_guard_is_closed_locally(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            buildlib.require_hosted()


class SpecRegressionTests(unittest.TestCase):
    def test_F1_normal_upstream_layout_no_pth_injection(self):
        text = (ROOT / 'scripts/build.py').read_text(encoding='utf-8')
        self.assertIn("'PC/layout/main.py'", text)
        self.assertIn("'--include-stable'", text)
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {'write_text', 'write_bytes'}:
                    self.assertNotIn('._pth', ast.unparse(node.func.value))

    def test_F2_actual_upstream_tier2_condition(self):
        import xml.etree.ElementTree as ET
        project_bytes = (UPSTREAM / 'PCbuild/pythoncore.vcxproj').read_bytes()
        buildlib.checked_hash(project_bytes, '92e6d58e0944658f0e33fe9022d39b9dae45d985024d03f82528620fdcc4bd4a')
        project = ET.fromstring(project_bytes)
        definition = next(n for n in project.iter() if n.text and '_Py_TIER2=$(UseTIER2)' in n.text)
        condition = definition.attrib['Condition']
        self.assertEqual(condition, "'$(UseTIER2)' != '' and '$(UseTIER2)' != '0'")
        # Evaluate exactly the two upstream comparisons, not MSBuild boolean spelling.
        def defines(value):
            return value != '' and value != '0'
        self.assertTrue(defines('false'))
        self.assertTrue(defines('1'))
        self.assertFalse(defines('0'))
        pins = json.loads((ROOT / 'pins.json').read_bytes())
        self.assertFalse(defines(pins['properties']['UseTIER2']))
        self.assertEqual(pins['properties']['UseJIT'], 'false')

    def test_F3_persisted_source_and_complete_recipe(self):
        text = (ROOT / 'scripts/build.py').read_text(encoding='utf-8')
        for name in ['source-original.json', 'source-post-patch.json', 'source-final.json',
                     'dependencies-final.json', 'recipe.json']:
            self.assertIn(name, text)
        self.assertIn('export_recipe(', text)

    def test_F4_records_upload_even_after_failure(self):
        steps = json.loads((ROOT / '.github/workflows/build.yml').read_bytes())['jobs']['build']['steps']
        upload = [s for s in steps if s.get('name') == 'Preserve diagnostic records']
        self.assertEqual(len(upload), 1)
        self.assertIn('always()', upload[0]['if'])
        self.assertEqual(upload[0]['with']['retention-days'], 3)
        self.assertNotEqual(upload[0]['with']['path'], '${{ steps.package.outputs.artifact }}')


class RepairFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEMP)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Own recipe only. Imported module defines functions and has a guarded main.
        import build
        self.build = build

    def put(self, name, data=b'ordinary inert fixture; not executable'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_inventory_exact_missing_extra_tamper(self):
        self.put('tree/include/header.h', b'header')
        self.put('tree/lib/input.lib', b'library')
        tree = self.root / 'tree'
        expected = buildlib.inventory(tree)
        buildlib.verify_inventory(tree, expected)
        for kind in ('missing', 'extra', 'tamper', 'renamed'):
            with self.subTest(kind=kind):
                file = tree / 'include/header.h'
                if kind == 'missing':
                    file.unlink()
                elif kind == 'extra':
                    (tree / 'extra.txt').write_bytes(b'extra')
                elif kind == 'renamed':
                    file.rename(tree / 'renamed.h')
                else:
                    file.write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    buildlib.verify_inventory(tree, expected)
                if kind == 'extra':
                    (tree / 'extra.txt').unlink()
                if kind == 'renamed':
                    (tree / 'renamed.h').unlink()
                file.write_bytes(b'header')
        buildlib.verify_inventory(tree, expected)

    def test_inventory_rejects_missing_root_and_unsafe_map(self):
        with self.assertRaises(ValueError):
            buildlib.inventory(self.root / 'missing')
        for name in ('../escape', 'C:/outside', './bad', 'dir//file'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                buildlib.verify_inventory(self.root, {name: '0' * 64})

    def test_archive_materialization_bound_to_actual_archive(self):
        archive = self.put('input.zip', b'inert archive-binding fixture')
        self.put('extracted/header.h', b'header')
        pin = {'sha256': buildlib.file_hash(archive), 'name': 'fixture'}
        record = buildlib.archive_inventory(archive, pin, self.root / 'extracted')
        self.assertEqual(record['files'], {'header.h': buildlib.digest(b'header')})
        self.assertEqual(record['archive_sha256'], pin['sha256'])
        archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            buildlib.archive_inventory(archive, pin, self.root / 'extracted')

    def test_recipe_export_complete_and_hash_bound(self):
        expected = buildlib.recipe_inventory(ROOT)
        destination = self.root / 'recipe'
        buildlib.export_recipe(ROOT, destination, expected)
        self.assertEqual(set(buildlib.inventory(destination)), buildlib.RECIPE_FILES)
        self.assertIn('.github/workflows/build.yml', expected)
        self.assertIn('tests/test_build.py', expected)
        manifest = buildlib.seal_directory(self.root)
        self.assertEqual(manifest['files'], {'recipe/' + p: h for p, h in expected.items()})
        self.assertEqual(manifest['self_exclusion'], 'manifest.json')
        for kind in ('missing', 'extra', 'tamper'):
            with self.subTest(kind=kind):
                target = destination / 'README.md'
                if kind == 'missing':
                    target.unlink()
                elif kind == 'extra':
                    (destination / 'unreviewed.txt').write_bytes(b'extra')
                else:
                    target.write_bytes(b'tamper')
                with self.assertRaises(ValueError):
                    buildlib.export_recipe(destination, self.root / ('rejected-' + kind), expected)
                if kind == 'extra':
                    (destination / 'unreviewed.txt').unlink()
                target.write_bytes((ROOT / 'README.md').read_bytes())

    def test_toolchain_root_snapshot_includes_header_lib_and_import(self):
        for name in ('include/header.h', 'lib/x64/runtime.lib', 'imports/tool.targets', 'bin/compiler.exe'):
            self.put('selected/' + name)
        records = self.root / 'records'
        records.mkdir()
        result = self.build.snapshot_roots({'selected': self.root / 'selected'}, records)
        actual = json.loads((records / 'input-selected.json').read_bytes())
        self.assertEqual(actual, result['selected'])
        self.assertEqual(set(actual['files']), {'include/header.h', 'lib/x64/runtime.lib',
                                               'imports/tool.targets', 'bin/compiler.exe'})
        with self.assertRaises(ValueError):
            self.build.snapshot_roots({'absent': self.root / 'absent'}, records)

    def test_source_final_records_include_generated_paths(self):
        for path in ('source/original.c', 'source/generated.h', 'externals/dep/header.h',
                     'obj/frozen/new.h', 'out/python.exe'):
            self.put('work/' + path)
        records = self.root / 'records'
        records.mkdir()
        self.build.capture_build_state(self.root / 'work', records)
        final = json.loads((records / 'source-final.json').read_bytes())
        self.assertEqual(set(final), {'original.c', 'generated.h'})
        self.assertEqual(set(json.loads((records / 'intermediates.json').read_bytes())), {'frozen/new.h'})
        self.assertEqual(set(json.loads((records / 'dependencies-final.json').read_bytes())), {'dep/header.h'})

    def test_helper_amendments_are_exact_flags_only(self):
        original = {}
        for name in buildlib.BUILD_HELPER_EDITS:
            original[name] = (UPSTREAM / name).read_bytes()
            self.put(name, original[name])
        changes = self.build.amend_build_helpers(self.root)
        self.assertEqual(set(changes), {'PCbuild/python.vcxproj', 'PCbuild/regen.targets'})
        for name, change in changes.items():
            updated = (self.root / name).read_bytes()
            self.assertEqual(updated, original[name].replace(change['old'].encode(), change['new'].encode()))
            self.assertEqual(change['new'].replace(' -S -B -s', ''), change['old'])
            self.assertEqual(buildlib.file_hash(self.root / name), change['after'])
        with self.assertRaises(ValueError):
            buildlib.amend_build_helpers(self.root)

    def test_helper_amendment_preflight_rejects_drift_without_partial_write(self):
        for name in buildlib.BUILD_HELPER_EDITS:
            self.put(name, (UPSTREAM / name).read_bytes())
        self.put('PCbuild/regen.targets', b'changed')
        before = buildlib.inventory(self.root)
        with self.assertRaises(ValueError):
            buildlib.amend_build_helpers(self.root)
        buildlib.verify_inventory(self.root, before)

    def test_pinned_helper_startup_trace(self):
        import xml.etree.ElementTree as ET
        freeze_bytes = (UPSTREAM / 'Programs/_freeze_module.c').read_bytes()
        buildlib.checked_hash(freeze_bytes, 'ddb95051b0993e421f70e80163d94827ec0889f172132fcd096dfd753f2992b4')
        freeze = freeze_bytes.decode('utf-8')
        self.assertIn('PyConfig_InitIsolatedConfig(&config);', freeze)
        self.assertIn('config.site_import = 0;', freeze)
        self.assertIn('config._install_importlib = 0;', freeze)
        self.assertIn('config._init_main = 0;', freeze)
        for filename in ('PCbuild/python.vcxproj', 'PCbuild/regen.targets'):
            tree = ET.fromstring((UPSTREAM / filename).read_bytes())
            raw = [n.attrib['Command'] for n in tree.iter() if n.tag.endswith('Exec')
                   and 'Command' in n.attrib and ('$(PythonExe)' in n.attrib['Command']
                       or '$(OutDir)$(PyExeName)$(PyDebugExt).exe' in n.attrib['Command'])]
            self.assertEqual(len(raw), 1)
            self.assertIn('set PYTHONPATH=$(PySourcePath)Lib', raw[0])
        text = (ROOT / 'scripts/build.py').read_text(encoding='utf-8')
        self.assertIn("'PythonForBuild': f'\"{sys.executable}\" -S -B -s'", text)
        regen = (UPSTREAM / 'PCbuild/regen.targets').read_text(encoding='utf-8')
        self.assertIn('set PYTHONPATH=Tools\\peg_generator', regen)

    def test_layout_exact_upstream_command(self):
        source, output, package, temp = [self.root / n for n in ('source', 'output', 'package', 'temp')]
        cmd = self.build.layout_command(source, output, package, temp)
        self.assertEqual(cmd, [output / 'python.exe', '-S', '-B', '-s', source / 'PC/layout/main.py',
                              '--source', source, '--build', output, '--copy', package, '--temp', temp,
                              '--arch', 'amd64', '--include-stable'])
        self.assertNotIn(sys.executable, cmd)
        for forbidden in ('--zip-lib', '--include-underpth', '--precompile', '--include-pip',
                          '--preset-embed', '--include-tests', '--include-all', '--flat-dlls'):
            self.assertNotIn(forbidden, cmd)

    def test_no_pth_anywhere_in_output_or_package(self):
        for name in ('out/python314._pth', 'package/nested/PYTHON._PTH'):
            path = self.put(name)
            with self.assertRaises(ValueError):
                buildlib.assert_no_pth(self.root)
            path.unlink()
        buildlib.assert_no_pth(self.root)

    def package_fixture(self):
        names = ['python.exe', 'pythonw.exe', 'python314.dll', 'python3.dll',
                 'Lib/os.py', 'Lib/encodings/__init__.py', 'LICENSE.txt', 'licenses/crtlicense.txt',
                 'DLLs/_bz2.pyd', 'DLLs/_hashlib.pyd', 'DLLs/_lzma.pyd', 'DLLs/_sqlite3.pyd',
                 'DLLs/_uuid.pyd', 'DLLs/_zstd.pyd', 'DLLs/unicodedata.pyd', 'DLLs/_ssl.pyd',
                 'DLLs/sqlite3.dll', 'DLLs/libcrypto-3.dll', 'DLLs/libssl-3.dll']
        for name in names:
            self.put('package/' + name)
        for folder, name in (('crt', 'vcruntime140.dll'), ('ucrt', 'ucrtbase.dll')):
            self.put(folder + '/' + name)
            self.put('package/' + name)
        return self.root / 'package', self.root / 'crt', self.root / 'ucrt'

    def test_package_positive_crt_and_missing_native_rejection(self):
        args = self.package_fixture()
        self.build.validate_package(*args)
        native = args[0] / 'DLLs/_ssl.pyd'
        native.unlink()
        with self.assertRaises(RuntimeError):
            self.build.validate_package(*args)

    def test_package_prohibitions_and_crt_tamper(self):
        args = self.package_fixture()
        for name in ('python314._pth', 'python314.zip', 'Lib/site-packages', 'Lib/ensurepip',
                     'Lib/test', 'Lib/cache.pyc', 'Lib/__pycache__', 'DLLs/_ctypes.pyd'):
            path = self.put('package/' + name)
            with self.subTest(name=name), self.assertRaises((ValueError, RuntimeError)):
                self.build.validate_package(*args)
            path.unlink()
        self.put('package/vcruntime140.dll', b'tampered')
        with self.assertRaises(ValueError):
            self.build.validate_package(*args)

    def test_make_package_uses_layout_and_copies_licenses(self):
        package, crt, ucrt = self.package_fixture()
        self.put('source/LICENSE', b'CPython license fixture')
        self.put('source/PC/crtlicense.txt', b'CRT license fixture')
        self.put('externals/dependency/LICENSE', b'native dependency license fixture')
        (package / 'licenses/crtlicense.txt').unlink()
        (package / 'licenses').rmdir()
        output = self.root / 'output'
        output.mkdir()
        records = self.root / 'records'
        records.mkdir()
        # Normal upstream layout also copies the actual stock placeholder.
        stock = buildlib.checked_hash((UPSTREAM / 'Lib/site-packages/README.txt').read_bytes(),
            'cba8fece8f62c36306ba27a128f124a257710e41fc619301ee97be93586917cb')
        self.put('source/Lib/site-packages/README.txt', stock)
        def layout(*args, **kwargs):
            self.put('package/Lib/site-packages/README.txt', stock)
        with mock.patch.object(self.build, 'run', side_effect=layout) as run:
            self.build.make_package(self.root / 'source', output, self.root / 'externals',
                                    package, crt, ucrt, self.root / 'temp', records, {})
        self.assertEqual(run.call_args.args[0], self.build.layout_command(
            self.root / 'source', output, package, self.root / 'temp'))
        self.assertEqual(run.call_args.kwargs['env'], {'PYTHONHOME': str(self.root / 'source'),
                                                       'PYTHONPATH': str(output)})
        self.assertEqual((package / 'licenses/crtlicense.txt').read_bytes(), b'CRT license fixture')
        self.assertEqual((package / 'licenses/dependency/LICENSE').read_bytes(), b'native dependency license fixture')
        buildlib.assert_no_pth(package)

    def test_native_inputs_and_compiler_token_detection(self):
        header = self.put('include/native.h', b'header')
        self.put('work/obj/core/CL.command.1.tlog', '^source.c\n/D NDEBUG /c source.c\n'.encode('utf-16'))
        self.put('work/obj/core/CL.read.1.tlog', ('^source.c\n' + str(header) + '\n').encode('utf-16'))
        records = self.root / 'records'
        records.mkdir()
        self.build.native_inputs(self.root / 'work', records)
        saved = json.loads((records / 'native-read-inputs.json').read_bytes())
        self.assertEqual(saved, {str(header): buildlib.file_hash(header)})
        self.put('work/obj/core/CL.command.1.tlog', '^source.c\n/D _Py_TIER2=false\n'.encode('utf-16'))
        failed = self.root / 'failed-records'
        failed.mkdir()
        with self.assertRaises(RuntimeError):
            self.build.native_inputs(self.root / 'work', failed)

    def test_credentials_not_forwarded(self):
        with mock.patch.dict(os.environ, {'PATH': 'unchanged', 'GITHUB_TOKEN': 'fixture-secret',
                                         'ACTIONS_RUNTIME_TOKEN': 'fixture-secret', 'PYTHONPATH': 'hostile',
                                         'CL': '/D _Py_TIER2=1', 'MSBuildSDKsPath': 'hostile'}, clear=True):
            env = self.build.child_environment()
        self.assertEqual(env, {'PATH': 'unchanged', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'})

    def test_real_ordinary_failure_preserves_only_records(self):
        records = self.root / 'records'
        records.mkdir()
        self.put('work/partial/python.exe', b'inert partial fixture; never executable')
        self.put('work/private-credentials.txt', b'fixture-secret')
        output = self.put('outputs.txt', b'')
        def operation():
            self.build.run([sys.executable, '-I', '-S', '-B', '-c', "print('earlier fixture success')"],
                           records / 'earlier.txt', cwd=self.root)
            buildlib.write_json(records / 'unexpected-source-changes.json', {'fixture.h': None})
            self.build.run([sys.executable, '-I', '-S', '-B', '-c', "print('ordinary fixture failure'); raise SystemExit(7)"],
                           records / 'failed.txt', cwd=self.root)
            self.fail('Failure must not become success')
        with mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), self.assertRaises(RuntimeError):
            self.build.recorded_pipeline(records, operation)
        self.assertEqual(output.read_bytes(), b'')
        status = json.loads((records / 'status.json').read_bytes())
        self.assertEqual(status['state'], 'failed')
        self.assertIs(status['runtime_exported'], False)
        cmd = json.loads((records / 'failed.command.json').read_bytes())
        self.assertEqual(cmd['returncode'], 7)
        self.assertIn('earlier fixture success', (records / 'earlier.txt').read_text())
        self.assertIn('ordinary fixture failure', (records / 'failed.txt').read_text())
        manifest = json.loads((records / 'manifest.json').read_bytes())
        files = buildlib.inventory(records)
        self.assertEqual(manifest['files'], {p: h for p, h in files.items() if p != 'manifest.json'})
        self.assertEqual(set(files), {'status.json', 'earlier.txt', 'earlier.command.json', 'failed.txt',
                                     'failed.command.json', 'unexpected-source-changes.json', 'manifest.json'})
        self.assertFalse(any(p.endswith(('.exe', '.dll', '.pyd')) for p in files))
        self.assertNotIn(b'fixture-secret', b''.join((records / n).read_bytes() for n in files))

    def test_success_seals_records_and_complete_artifact(self):
        records = self.root / 'records'
        records.mkdir()
        self.put('records/log.txt', b'fixture success')
        artifact = self.root / 'artifact'
        artifact.mkdir()
        buildlib.export_recipe(ROOT, artifact / 'recipe', buildlib.recipe_inventory(ROOT))
        result = self.build.recorded_pipeline(records, lambda: artifact)
        self.assertEqual(result, artifact)
        manifest = json.loads((artifact / 'manifest.json').read_bytes())
        current = buildlib.inventory(artifact)
        current.pop('manifest.json')
        self.assertEqual(current, manifest['files'])
        self.assertIn('recipe/.github/workflows/build.yml', current)
        self.assertIn('recipe/tests/test_build.py', current)


class ConfigurationTests(unittest.TestCase):
    def test_workflow_surface(self):
        workflow = json.loads((ROOT / '.github/workflows/build.yml').read_bytes())
        self.assertEqual(workflow['on'], {'workflow_dispatch': {}})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertIs(workflow['concurrency']['cancel-in-progress'], False)
        self.assertIn('github.run_id', workflow['concurrency']['group'])
        job = workflow['jobs']['build']
        self.assertEqual(job['runs-on'], 'windows-2022')
        self.assertLessEqual(job['timeout-minutes'], 90)
        pins = json.loads((ROOT / 'pins.json').read_bytes())
        for step in job['steps']:
            if 'uses' in step:
                repo, commit = step['uses'].split('@')
                self.assertRegex(commit, r'^[0-9a-f]{40}$')
                self.assertEqual(commit, pins['actions'][repo])
        checkout = next(s for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        self.assertIs(checkout['with']['persist-credentials'], False)
        self.assertEqual(job['steps'][-1]['with']['retention-days'], 3)
        self.assertNotIn('${{ secrets.', json.dumps(workflow))
        self.assertNotIn('pull_request', workflow['on'])
        self.assertNotIn('push', workflow['on'])

    def test_properties_and_source_pins(self):
        pins = json.loads((ROOT / 'pins.json').read_bytes())
        expected = {'Configuration': 'Release', 'Platform': 'x64', 'PlatformToolset': 'v143',
                    'IncludeExtensions': 'true', 'IncludeExternals': 'true', 'IncludeSSL': 'true',
                    'IncludeCTypes': 'false', 'IncludeTkinter': 'false', 'IncludeTests': 'false',
                    'IncludeTest': 'false', 'DisableGil': 'false', 'UseJIT': 'false',
                    'UseTIER2': '0', 'KillPython': 'false'}
        for key, value in expected.items():
            self.assertEqual(pins['properties'][key], value)
        self.assertEqual(pins['source']['commit'], '823f0323ee6ec1402088b73bce1a38473cac36dc')
        self.assertEqual(pins['source']['identity'], 'hugo@python.org')
        self.assertEqual(pins['source']['issuer'], 'https://github.com/login/oauth')
        self.assertEqual(len(pins['dependencies']), 7)
        for dep in pins['dependencies']:
            self.assertIn(dep['repository'], ['python/cpython-source-deps', 'python/cpython-bin-deps'])
            self.assertRegex(dep['commit'], r'^[0-9a-f]{40}$')
            self.assertTrue(dep['url'].endswith('/zip/' + dep['commit']))
            self.assertRegex(dep['sha256'], r'^[0-9a-f]{64}$')

    def test_verifier_lock(self):
        lock = json.loads((ROOT / 'sigstore-wheels.lock.json').read_bytes())
        names = [w['name'].lower() for w in lock['wheels']]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 32)
        for wheel in lock['wheels']:
            self.assertRegex(wheel['sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(wheel['filename'].endswith('.whl'))
            self.assertTrue(wheel['url'].startswith('https://files.pythonhosted.org/'))
        self.assertEqual(next(w['version'] for w in lock['wheels'] if w['name'] == 'sigstore'), '4.5.0')

    def test_python_syntax_and_hosted_entrypoints(self):
        for file in ROOT.rglob('*.py'):
            tree = ast.parse(file.read_text(encoding='utf-8'), filename=file.name)
            compile(tree, file.name, 'exec')  # Parse/compile only: do not execute gate or downloaded code.
            if file.name in {'build.py', 'verify_source.py'}:
                main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
                self.assertEqual(ast.unparse(main.body[0]), 'require_hosted()')

    def test_gate_eight_cases_without_running_it(self):
        tree = ast.parse((ROOT / 'scripts/audit_gate.py').read_text(encoding='utf-8'))
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        cases = next(n.value for n in main.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'cases' for t in n.targets))
        self.assertEqual(len(cases.elts), 8)
        self.assertEqual([n.elts[0].value[:2] for n in cases.elts], [f'A{i}' for i in range(1, 9)])
        hook = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'audit')
        self.assertIsInstance(hook.body[0].body[-1], ast.Raise)
        self.assertEqual(ast.unparse(hook.body[0].body[-1]), 'raise denial')

    def test_no_unsafe_build_entrypoints(self):
        text = '\n'.join(p.read_text(encoding='utf-8') for p in (ROOT / 'scripts').glob('*.py'))
        for forbidden in ['build.bat', 'find_python.bat', 'get_externals.bat', 'pip install',
                          'taskkill', 'Stop-Process', '/t:Clean', '/t:Rebuild', '/p:PGO', 'shell=True']:
            self.assertNotIn(forbidden, text)
        self.assertIn("'/m:1'", text)
        self.assertIn("'/noAutoResponse'", text)
        self.assertIn("'UserRootDir'", text)

    def test_failure_and_success_upload_boundaries(self):
        steps = json.loads((ROOT / '.github/workflows/build.yml').read_bytes())['jobs']['build']['steps']
        self.assertEqual(steps[0]['id'], 'records')
        self.assertIn('GITHUB_OUTPUT', steps[0]['run'])
        self.assertIn('workflow-status.json', steps[0]['run'])
        uploads = [s for s in steps if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 2)
        records, runtime = uploads
        self.assertEqual(records['with']['path'], '${{ steps.records.outputs.records }}')
        self.assertEqual(runtime['with']['path'], '${{ steps.package.outputs.artifact }}')
        self.assertIn('always()', records['if'])
        self.assertIn('success()', runtime['if'])
        self.assertIn("steps.package.outcome == 'success'", runtime['if'])
        self.assertIs(runtime['with']['include-hidden-files'], True)
        self.assertNotIn('continue-on-error', json.dumps(steps))
        package = next(s for s in steps if s.get('id') == 'package')
        self.assertIn('--records $env:RECORDS_DIR', package['run'])
        self.assertTrue(package['run'].rstrip().endswith('throw\n}'))
        for upload in uploads:
            self.assertEqual(upload['with']['retention-days'], 3)
        self.assertIn('Hard runner loss', (ROOT / 'README.md').read_text(encoding='utf-8'))

    def test_verifier_inventories_precede_downloaded_execution(self):
        text = (ROOT / 'scripts/verify_source.py').read_text(encoding='utf-8')
        self.assertLess(text.index("'verifier-inputs.json'"), text.index('from packaging.requirements import'))
        self.assertIn('archive_inventory(archive, wheel, target)', text)
        build = (ROOT / 'scripts/build.py').read_text(encoding='utf-8')
        for root_name in ('msvc', 'sdk-headers', 'sdk-ucrt-libs', 'sdk-um-libs', 'sdk-imports',
                          'msbuild', 'bootstrap', 'framework', 'vc-auxiliary'):
            self.assertIn("'" + root_name + "'", build)
        self.assertIn("'native-read-inputs.json'", build)
        self.assertIn("'compiler-configuration.json'", build)

    def test_public_allowlist_and_path_hygiene(self):
        expected = {'.gitattributes', '.github/workflows/build.yml', 'README.md', 'pins.json',
                    'sigstore-wheels.lock.json', 'scripts/buildlib.py', 'scripts/build.py',
                    'scripts/verify_source.py', 'scripts/audit_gate.py', 'tests/test_build.py'}
        actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
                  if p.is_file() and '.git' not in p.relative_to(ROOT).parts}
        self.assertEqual(actual, expected)
        for name in actual:
            text = (ROOT / name).read_text(encoding='utf-8')
            # Construct negative tokens so the hygiene test does not contain them itself.
            self.assertNotIn('C:' + '/Users/', text)
            self.assertNotIn('C:' + '\\Users\\', text)
            self.assertNotIn('-----BEGIN ' + 'PRIVATE KEY-----', text)
            self.assertNotIn('gh' + 'p_', text)


class PackagingHelperTests(unittest.TestCase):
    APPX = 'PC/layout/support/appxmanifest.py'
    BEFORE = '2ebfde12fd1c8a12b3c48ac3081ab018e68c633cb64d59b1ad0bceec5ad8af21'
    AFTER = 'b80520a2a5098aa1e154216cbcb02bb77ff7f7e6ca3299929b3718d175e18e26'
    SIGNATURE = b'def get_packagefamilyname(name, publisher_id):\n'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEMP)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        import build  # Owned function definitions only; never execute build main.
        self.build = build
        self.original = self.pinned(self.APPX, self.BEFORE)
        for name, data in [(self.APPX, self.original), *[
                (name, self.pinned(name, value[0]))
                for name, value in buildlib.BUILD_HELPER_EDITS.items()]]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.root / 'unrelated.txt').write_bytes(b'unchanged inert fixture')

    def pinned(self, name, expected):
        data = (UPSTREAM / name).read_bytes()
        self.assertEqual(buildlib.digest(data), expected, name)
        return data

    def registered_amendments(self):
        # Read actual recipe wiring, execute only its named owned byte helpers.
        # No exec/eval/import of an upstream AST, module, or build pipeline.
        tree = ast.parse((ROOT / 'scripts/build.py').read_text(encoding='utf-8'))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'perform_build')
        calls = []
        for statement in function.body:
            if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                continue
            call = statement.value
            if not isinstance(call.func, ast.Name) or call.func.id != 'write_json' or len(call.args) != 2:
                continue
            amendment = call.args[1]
            if (isinstance(amendment, ast.Call) and isinstance(amendment.func, ast.Name)
                    and amendment.func.id in {'amend_build_helpers', 'amend_packaging_helper'}):
                self.assertEqual(ast.unparse(amendment.args[0]), 'source')
                calls.append((ast.unparse(call.args[0]), amendment.func.id, statement.lineno))
        self.assertTrue(calls)
        return calls, function

    def prepare_fixture(self):
        changes = {}
        for record, name, _ in self.registered_amendments()[0]:
            changes[record] = getattr(buildlib, name)(self.root)
        return changes

    def unconditional_chain(self, appx):
        import xml.etree.ElementTree as ET
        main = ast.parse(self.pinned('PC/layout/main.py',
            '87536e40bffcdd8f6c1f9eb7d6b09bb61aed7c023c301ebd6ed059c88c7a1bf7'))
        ctypes = ast.parse(self.pinned('Lib/ctypes/__init__.py',
            '72f2df568380c275a5596944810953124ff2ee8d678c5f8ddcf50f0f77577eb3'))
        self.assertTrue(any(isinstance(n, ast.ImportFrom) and n.level == 1
                            and n.module == 'support.appxmanifest'
                            and [a.name for a in n.names] == ['*'] for n in main.body))
        self.assertTrue(any(isinstance(n, ast.ImportFrom) and n.module == '_ctypes'
                            and [a.name for a in n.names] == ['Union', 'Structure', 'Array']
                            for n in ctypes.body))
        project = ET.fromstring(self.pinned('PCbuild/pcbuild.proj',
            'b9cd7839e82914cfb1edf3812615412983b5b190b2494b54a89b74eab49d6f9a'))
        native = [n for n in project.iter() if n.attrib.get('Include') == '_ctypes']
        self.assertEqual(len(native), 1)
        self.assertEqual(native[0].attrib['Condition'], '$(IncludeCTypes)')
        self.assertEqual(json.loads((ROOT / 'pins.json').read_bytes())['properties']['IncludeCTypes'], 'false')
        if any(isinstance(n, ast.Import) and any(a.name == 'ctypes' for a in n.names)
               for n in ast.parse(appx).body):
            return ['PC/layout/main.py', self.APPX, 'Lib/ctypes/__init__.py', '_ctypes']
        return []

    def test_original_actual_unconditional_import_graph(self):
        self.assertEqual(self.unconditional_chain(self.original),
                         ['PC/layout/main.py', self.APPX, 'Lib/ctypes/__init__.py', '_ctypes'])

    def test_prepared_layout_breaks_unconditional_ctypes_chain(self):
        self.assertTrue(self.unconditional_chain(self.original))
        self.prepare_fixture()
        self.assertEqual(self.unconditional_chain((self.root / self.APPX).read_bytes()), [],
                         'Prepared normal layout must not unconditionally require disabled _ctypes')

    def test_exact_packaging_bytes_and_separate_three_file_inventory(self):
        before = buildlib.inventory(self.root)
        records = self.prepare_fixture()
        expected = self.original.replace(b'import ctypes\n', b'').replace(
            self.SIGNATURE, self.SIGNATURE + b'    import ctypes\n\n')
        self.assertEqual(self.original.count(b'import ctypes\n'), 1)
        self.assertEqual(self.original.count(self.SIGNATURE), 1)
        actual = (self.root / self.APPX).read_bytes()
        self.assertEqual(actual, expected)
        self.assertEqual(buildlib.digest(actual), self.AFTER)
        after = buildlib.inventory(self.root)
        self.assertEqual(set(before), set(after))
        self.assertEqual({n for n in before if before[n] != after[n]},
                         {self.APPX, 'PCbuild/python.vcxproj', 'PCbuild/regen.targets'})
        self.assertEqual(after['PCbuild/python.vcxproj'],
                         '8caaf383cf9a155d480c36b977fd5cb8a694d7519e863708f899b1c41d715336')
        self.assertEqual(after['PCbuild/regen.targets'],
                         'b1298d352db294b1763f91d2b4b3ae5eb994f019cc3a16bb25524b31791a3873')
        packaging = records["records / 'packaging-helper-amendment.json'"]
        self.assertEqual(set(packaging), {self.APPX})
        self.assertEqual(packaging[self.APPX]['before'], self.BEFORE)
        self.assertEqual(packaging[self.APPX]['after'], self.AFTER)
        self.assertIn('packaging-only', packaging[self.APPX]['scope'])
        self.assertEqual(set(records["records / 'build-helper-amendments.json'"]),
                         {'PCbuild/python.vcxproj', 'PCbuild/regen.targets'})

    def test_ctypes_binding_local_to_its_only_reference_function(self):
        self.prepare_fixture()
        tree = ast.parse((self.root / self.APPX).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'get_packagefamilyname')
        imports = [n for n in ast.walk(tree) if isinstance(n, ast.Import)
                   and any(a.name == 'ctypes' for a in n.names)]
        self.assertEqual(imports, [function.body[0]])
        self.assertEqual(ast.unparse(imports[0]), 'import ctypes')
        references = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == 'ctypes']
        self.assertTrue(references)
        self.assertTrue(all(n in set(ast.walk(function)) for n in references))
        self.assertTrue(all(isinstance(n.ctx, ast.Load) for n in references))
        # Reversing precisely the import relocation restores the entire original AST.
        moved = function.body.pop(0)
        original_tree = ast.parse(self.original)
        index = next(i for i, n in enumerate(original_tree.body)
                     if isinstance(n, ast.Import) and n.names[0].name == 'ctypes')
        tree.body.insert(index, moved)
        self.assertEqual(ast.dump(tree), ast.dump(original_tree))

    def test_packaging_preflight_rejects_changed_and_already_amended_without_write(self):
        target = self.root / self.APPX
        amended = self.original.replace(b'import ctypes\n', b'').replace(
            self.SIGNATURE, self.SIGNATURE + b'    import ctypes\n\n')
        for data in [b'', self.original + b'\n', self.original.replace(b'import ctypes\n', b''), amended]:
            with self.subTest(sha256=buildlib.digest(data)):
                target.write_bytes(data)
                before = buildlib.inventory(self.root)
                with self.assertRaises(ValueError):
                    buildlib.amend_packaging_helper(self.root)
                buildlib.verify_inventory(self.root, before)
        target.unlink()
        before = buildlib.inventory(self.root)
        with self.assertRaises(FileNotFoundError):
            buildlib.amend_packaging_helper(self.root)
        buildlib.verify_inventory(self.root, before)

    def test_packaging_expected_after_hash_checked_before_write(self):
        before = buildlib.inventory(self.root)
        with mock.patch.object(buildlib, 'APPX_HELPER_AFTER', '0' * 64):
            with self.assertRaises(ValueError):
                buildlib.amend_packaging_helper(self.root)
        buildlib.verify_inventory(self.root, before)

    def test_packaging_amendment_registered_before_prepared_inventory(self):
        calls, function = self.registered_amendments()
        self.assertEqual([(record, name) for record, name, _ in calls], [
            ("records / 'build-helper-amendments.json'", 'amend_build_helpers'),
            ("records / 'packaging-helper-amendment.json'", 'amend_packaging_helper')])
        prepared = next(n for n in function.body if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == 'prepared' for t in n.targets))
        self.assertEqual(ast.unparse(prepared.value), 'inventory(source)')
        self.assertLess(calls[0][2], calls[1][2])
        self.assertLess(calls[1][2], prepared.lineno)

    def test_actual_normal_layout_does_not_select_appx(self):
        options = ast.parse(self.pinned('PC/layout/support/options.py',
            '2db5a6b14f05ee039fd60302e5cefdc8b59c5da0f8ae92ef7167b39decd87af2'))
        values = {n.targets[0].id: ast.literal_eval(n.value) for n in options.body
                  if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                  and n.targets[0].id in {'OPTIONS', 'PRESETS'}}
        self.assertIn('appxmanifest', values['OPTIONS'])
        self.assertIn('appxmanifest', values['PRESETS']['appx']['options'])
        main = ast.parse(self.pinned('PC/layout/main.py',
            '87536e40bffcdd8f6c1f9eb7d6b09bb61aed7c023c301ebd6ed059c88c7a1bf7'))
        self.assertTrue(any(isinstance(n, ast.For) and isinstance(n.iter, ast.Call)
                            and ast.unparse(n.iter) == 'get_argparse_options()'
                            and ast.unparse(n.body[0]) == "parser.add_argument(opt, help=help, action='store_true')"
                            for n in ast.walk(main)))
        command = self.build.layout_command(*(self.root / n for n in ('source', 'out', 'package', 'temp')))
        selected = [arg for arg in command if isinstance(arg, str) and arg.startswith(('--include-', '--preset-'))]
        self.assertEqual(selected, ['--include-stable'])
        update = next(n for n in options.body if isinstance(n, ast.FunctionDef) and n.name == 'update_presets')
        self.assertEqual(ast.unparse(update.body[0].body[0].test), "ns_get(ns, 'preset-{}'.format(preset))")
        self.assertEqual(ast.unparse(update.body[1].test), 'ns.include_all')
        appx = ast.parse(self.original)
        guard = next(n for n in appx.body if isinstance(n, ast.FunctionDef) and n.name == 'get_appx_layout').body[0]
        self.assertEqual(ast.unparse(guard), 'if not ns.include_appxmanifest:\n    return')


class StockPlaceholderTests(unittest.TestCase):
    """Source-bound Q1 regressions; no upstream imports or execution."""
    MEMBER = 'Lib/site-packages/README.txt'
    SHA256 = 'cba8fece8f62c36306ba27a128f124a257710e41fc619301ee97be93586917cb'
    RECORD = 'package-placeholder-cleanup.json'
    setUp = RepairFixtureTests.setUp
    put = RepairFixtureTests.put
    package_fixture = RepairFixtureTests.package_fixture

    def stock(self):
        data = (UPSTREAM / self.MEMBER).read_bytes()
        self.assertEqual(buildlib.digest(data), self.SHA256)
        self.assertEqual(len(data), 119)
        return data

    def placeholder_fixture(self, tag=''):
        base = self.root / tag
        for tree in ('source', 'package'):
            path = base / tree / self.MEMBER
            path.parent.mkdir(parents=True)
            path.write_bytes(self.stock())
        records = base / 'records'
        records.mkdir()
        return base / 'source', base / 'package', records

    def receipt(self, records):
        return json.loads((records / self.RECORD).read_bytes())

    def test_Q1_selected_normal_layout_includes_actual_placeholder(self):
        import fnmatch
        main_bytes = (UPSTREAM / 'PC/layout/main.py').read_bytes()
        self.assertEqual(buildlib.digest(main_bytes),
                         '87536e40bffcdd8f6c1f9eb7d6b09bb61aed7c023c301ebd6ed059c88c7a1bf7')
        tree = ast.parse(main_bytes)
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        lib = functions['get_lib_layout']
        expected = ast.parse('''def _c(f):
    if f in EXCLUDE_FROM_LIB:
        return False
    if f.is_dir():
        if f in TEST_DIRS_ONLY:
            return ns.include_tests
        if f in TCLTK_DIRS_ONLY:
            return ns.include_tcltk
        if f in IDLE_DIRS_ONLY:
            return ns.include_idle
        if f in VENV_DIRS_ONLY:
            return ns.include_venv
    else:
        if f in TCLTK_FILES_ONLY:
            return ns.include_tcltk
    return True
''').body[0]
        self.assertEqual(ast.dump(lib.body[0]), ast.dump(expected))
        self.assertEqual(ast.unparse(lib.body[1]),
                         "for dest, src in rglob(ns.source / 'Lib', '**/*', _c):\n    yield (dest, src)")
        sets = {n.targets[0].id: [ast.literal_eval(a) for a in n.value.args]
                for n in tree.body if isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call)
                and ast.unparse(n.value.func) == 'FileNameSet'}
        # Owned reasoning over the exact inspected predicate, not eval/exec of it.
        for name, exclusions in (
                ('site-packages', ('EXCLUDE_FROM_LIB', 'TEST_DIRS_ONLY', 'TCLTK_DIRS_ONLY',
                                   'IDLE_DIRS_ONLY', 'VENV_DIRS_ONLY')),
                ('README.txt', ('EXCLUDE_FROM_LIB', 'TCLTK_FILES_ONLY'))):
            for exclusion in exclusions:
                self.assertFalse(any(fnmatch.fnmatchcase(name.lower(), p.lower()) for p in sets[exclusion]))
        normal = next(n for n in functions['get_layout'].body
                      if isinstance(n, ast.If) and ast.unparse(n.test) == 'ns.zip_lib')
        self.assertEqual(ast.unparse(normal.orelse[0]),
                         "for dest, src in get_lib_layout(ns):\n    yield ('Lib/{}'.format(dest), src)")
        pip = next(n for n in functions['get_layout'].body
                   if isinstance(n, ast.If) and ast.unparse(n.test) == 'ns.include_pip')
        references = [n for n in ast.walk(functions['get_layout'])
                      if isinstance(n, ast.Name) and n.id == 'EXCLUDE_FROM_PACKAGED_LIB']
        self.assertEqual(len(references), 1)
        self.assertIn(references[0], list(ast.walk(pip)))
        self.assertEqual(sets['EXCLUDE_FROM_PACKAGED_LIB'], ['readme.txt'])
        fs_bytes = (UPSTREAM / 'PC/layout/support/filesets.py').read_bytes()
        self.assertEqual(buildlib.digest(fs_bytes),
                         '8a98b5670f850e47836cb51ab45d2778a72407fe65d335390796c71bdd3617d8')
        fs = ast.parse(fs_bytes)
        glob = next(n for n in fs.body if isinstance(n, ast.FunctionDef) and n.name == '_rglob')
        text = ast.unparse(glob)
        self.assertIn('filter(condition, (type(root)(f2) for f2 in os.scandir(d) if f2.is_dir()))', text)
        self.assertIn('if f.is_file() and condition(f)', text)
        copies = [n for n in ast.walk(functions['copy_files'])
                  if isinstance(n, ast.If) and ast.unparse(n.test) == 'ns.copy'
                  and 'copy_if_modified(src, ns.copy / dest)' in ast.unparse(n)]
        self.assertEqual(len(copies), 1)
        self.assertIn('(ns.copy / dest).parent.mkdir(parents=True, exist_ok=True)', ast.unparse(copies[0]))
        command = self.build.layout_command(*(self.root / n for n in ('source', 'out', 'package', 'temp')))
        self.assertNotIn('--zip-lib', command)
        self.assertNotIn('--include-pip', command)
        self.stock()

    def test_Q1_make_package_composes_realistic_layout_cleanup_and_validator(self):
        package, crt, ucrt = self.package_fixture()
        self.put('source/LICENSE', b'CPython license fixture')
        self.put('source/PC/crtlicense.txt', b'CRT license fixture')
        self.put('source/' + self.MEMBER, self.stock())
        self.put('externals/dependency/LICENSE', b'dependency license fixture')
        (package / 'licenses/crtlicense.txt').unlink()
        (package / 'licenses').rmdir()
        output, records = self.root / 'output', self.root / 'records'
        output.mkdir()
        records.mkdir()
        source_before = buildlib.inventory(self.root / 'source')
        events = []
        def layout(*args, **kwargs):
            events.append('layout')
            self.put('package/' + self.MEMBER, (self.root / 'source' / self.MEMBER).read_bytes())
            self.assertEqual(buildlib.file_hash(package / self.MEMBER), self.SHA256)
        validate = self.build.validate_package
        def observed_validator(*args):
            events.append('validate')
            # Real validator first: unchanged predecessor must fail on actual stock output.
            validate(*args)
            self.assertFalse((package / 'Lib/site-packages').exists())
            self.assertEqual(self.receipt(records)['state'], 'passed')
        with mock.patch.object(self.build, 'run', side_effect=layout) as run, \
                mock.patch.object(self.build, 'validate_package', side_effect=observed_validator):
            self.build.make_package(self.root / 'source', output, self.root / 'externals',
                                    package, crt, ucrt, self.root / 'temp', records, {})
        self.assertEqual(events, ['layout', 'validate'])
        run.assert_called_once()
        self.assertEqual(buildlib.inventory(self.root / 'source'), source_before)
        self.assertEqual(self.receipt(records)['removed_files'], {self.MEMBER: self.SHA256})

    def test_exact_cleanup_and_records_export_without_source_changes(self):
        source, package, records = self.placeholder_fixture()
        before = buildlib.inventory(source)
        operations = []
        unlink, rmdir = Path.unlink, Path.rmdir
        def observed_unlink(path, *args, **kwargs):
            operations.append(('unlink', path.relative_to(package).as_posix()))
            return unlink(path, *args, **kwargs)
        def observed_rmdir(path, *args, **kwargs):
            operations.append(('rmdir', path.relative_to(package).as_posix()))
            return rmdir(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', observed_unlink), \
                mock.patch.object(Path, 'rmdir', observed_rmdir), \
                mock.patch.object(self.build.shutil, 'rmtree', side_effect=AssertionError('recursive deletion')):
            self.build.cleanup_stock_site_packages(source, package, records)
        self.assertEqual(operations, [('unlink', self.MEMBER), ('rmdir', 'Lib/site-packages')])
        self.assertEqual(buildlib.inventory(source), before)
        self.assertFalse((package / 'Lib/site-packages').exists())
        receipt = self.receipt(records)
        self.assertEqual(receipt['state'], 'passed')
        self.assertEqual(receipt['removed_files'], {self.MEMBER: self.SHA256})
        self.assertEqual(receipt['removed_directories'], ['Lib/site-packages'])
        self.assertEqual(receipt['source_sha256'], self.SHA256)
        self.assertEqual(receipt['package_sha256'], self.SHA256)
        artifact = self.root / 'artifact'
        artifact.mkdir()
        self.build.recorded_pipeline(records, lambda: artifact)
        self.assertEqual((artifact / 'records' / self.RECORD).read_bytes(), (records / self.RECORD).read_bytes())
        manifest = json.loads((artifact / 'manifest.json').read_bytes())
        self.assertEqual(manifest['files']['records/' + self.RECORD], buildlib.file_hash(records / self.RECORD))

    def test_rejects_unexpected_content_before_any_deletion(self):
        for tree in ('source', 'package'):
            for kind in ('wrong-hash', 'extra-file', 'extra-dir', 'missing-readme',
                         'empty-readme', 'missing-site', 'readme-directory', 'site-file'):
                with self.subTest(tree=tree, kind=kind):
                    source, package, records = self.placeholder_fixture(tree + '-' + kind)
                    target = (source if tree == 'source' else package) / self.MEMBER
                    if kind == 'wrong-hash':
                        target.write_bytes(b'x' * 119)
                    elif kind == 'extra-file':
                        (target.parent / 'extra.txt').write_bytes(b'extra')
                    elif kind == 'extra-dir':
                        (target.parent / 'extra').mkdir()
                    elif kind == 'empty-readme':
                        target.write_bytes(b'')
                    else:
                        target.unlink()
                        if kind == 'readme-directory':
                            target.mkdir()
                        elif kind in ('missing-site', 'site-file'):
                            target.parent.rmdir()
                            if kind == 'site-file':
                                target.parent.write_bytes(b'not a directory')
                    before = {t: buildlib.inventory(p) for t, p in [('source', source), ('package', package)]}
                    with mock.patch.object(Path, 'unlink') as unlink, mock.patch.object(Path, 'rmdir') as rmdir:
                        with self.assertRaises((ValueError, OSError)):
                            self.build.cleanup_stock_site_packages(source, package, records)
                        unlink.assert_not_called()
                        rmdir.assert_not_called()
                    self.assertEqual(before, {t: buildlib.inventory(p) for t, p in [('source', source), ('package', package)]})
                    receipt = self.receipt(records)
                    self.assertEqual(receipt['state'], 'failed')
                    self.assertEqual(receipt['removed_files'], {})
                    self.assertEqual(receipt['removed_directories'], [])

    def test_reparse_attributes_rejected_on_every_bounded_component(self):
        from types import SimpleNamespace
        for tree in ('source', 'package'):
            for relative in ('', 'Lib', 'Lib/site-packages', self.MEMBER):
                with self.subTest(tree=tree, relative=relative):
                    tag = tree + '-' + (relative.replace('/', '-') or 'root')
                    source, package, records = self.placeholder_fixture(tag)
                    target = (source if tree == 'source' else package) / relative
                    before = buildlib.inventory(source), buildlib.inventory(package)
                    real_lstat = Path.lstat
                    def lstat(path, *args, **kwargs):
                        value = real_lstat(path, *args, **kwargs)
                        if path == target:
                            return SimpleNamespace(st_mode=value.st_mode, st_nlink=value.st_nlink,
                                                   st_size=value.st_size, st_file_attributes=0x400)
                        return value
                    with mock.patch.object(Path, 'lstat', lstat), \
                            mock.patch.object(Path, 'unlink') as unlink, mock.patch.object(Path, 'rmdir') as rmdir:
                        with self.assertRaises(ValueError):
                            self.build.cleanup_stock_site_packages(source, package, records)
                        unlink.assert_not_called()
                        rmdir.assert_not_called()
                    self.assertEqual(before, (buildlib.inventory(source), buildlib.inventory(package)))
                    self.assertEqual(self.receipt(records)['removed_files'], {})

    def test_real_symlinks_rejected_without_touching_owned_targets(self):
        for tree in ('source', 'package'):
            for relative in ('', 'Lib', 'Lib/site-packages', self.MEMBER):
                with self.subTest(tree=tree, relative=relative):
                    tag = tree + '-' + (relative.replace('/', '-') or 'root')
                    source, package, records = self.placeholder_fixture(tag)
                    target = (source if tree == 'source' else package) / relative
                    saved = target.with_name(target.name + '-saved')
                    directory = target.is_dir()
                    target.rename(saved)
                    try:
                        target.symlink_to(saved, target_is_directory=directory)
                    except OSError as exc:
                        saved.rename(target)
                        self.skipTest('Real symlink creation unavailable: ' + type(exc).__name__)
                    try:
                        before = buildlib.inventory(saved) if directory else saved.read_bytes()
                        with mock.patch.object(Path, 'unlink') as unlink, mock.patch.object(Path, 'rmdir') as rmdir:
                            with self.assertRaises(ValueError):
                                self.build.cleanup_stock_site_packages(source, package, records)
                            unlink.assert_not_called()
                            rmdir.assert_not_called()
                        self.assertTrue(target.is_symlink())
                        self.assertEqual(before, buildlib.inventory(saved) if directory else saved.read_bytes())
                    finally:
                        target.unlink()
                        saved.rename(target)

    def test_real_hardlink_rejected_without_deletion(self):
        source, package, records = self.placeholder_fixture()
        target = package / self.MEMBER
        target.unlink()
        target.hardlink_to(source / self.MEMBER)
        with mock.patch.object(Path, 'unlink') as unlink, mock.patch.object(Path, 'rmdir') as rmdir:
            with self.assertRaises(ValueError):
                self.build.cleanup_stock_site_packages(source, package, records)
            unlink.assert_not_called()
            rmdir.assert_not_called()
        self.assertEqual(target.read_bytes(), self.stock())
        self.assertEqual((source / self.MEMBER).read_bytes(), self.stock())

    def test_source_package_alias_rejected(self):
        source, package, records = self.placeholder_fixture()
        before = buildlib.inventory(source)
        with mock.patch.object(Path, 'unlink') as unlink, mock.patch.object(Path, 'rmdir') as rmdir:
            with self.assertRaises(ValueError):
                self.build.cleanup_stock_site_packages(source, source, records)
            unlink.assert_not_called()
            rmdir.assert_not_called()
        self.assertEqual(buildlib.inventory(source), before)

    def test_cleanup_operation_failures_are_truthfully_recorded(self):
        for phase in ('unlink', 'rmdir'):
            with self.subTest(phase=phase):
                source, package, records = self.placeholder_fixture(phase)
                before = buildlib.inventory(source)
                with mock.patch.object(Path, phase, side_effect=PermissionError('fixture denial')):
                    with self.assertRaises(PermissionError):
                        self.build.cleanup_stock_site_packages(source, package, records)
                receipt = self.receipt(records)
                self.assertEqual(receipt['state'], 'failed')
                self.assertEqual(receipt['phase'], phase)
                self.assertEqual(receipt['exception_type'], 'PermissionError')
                self.assertEqual(receipt['removed_directories'], [])
                self.assertEqual(receipt['removed_files'], {} if phase == 'unlink' else {self.MEMBER: self.SHA256})
                self.assertEqual((package / self.MEMBER).exists(), phase == 'unlink')
                self.assertTrue((package / 'Lib/site-packages').is_dir())
                self.assertEqual(buildlib.inventory(source), before)

    def test_receipt_initialization_failure_prevents_deletion(self):
        source, package, records = self.placeholder_fixture()
        before = buildlib.inventory(package)
        with mock.patch.object(self.build, 'write_json', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError):
                self.build.cleanup_stock_site_packages(source, package, records)
        self.assertEqual(buildlib.inventory(package), before)

    def test_strict_validator_still_rejects_stock_and_arbitrary_site_packages(self):
        package, crt, ucrt = self.package_fixture()
        for data in (self.stock(), b'arbitrary third-party content'):
            self.put('package/' + self.MEMBER, data)
            with self.assertRaisesRegex(RuntimeError, 'Excluded package member: Lib/site-packages'):
                self.build.validate_package(package, crt, ucrt)


class InventoryDiagnosticTests(unittest.TestCase):
    """Inert link-diagnostic seams, not identification of any hosted link."""
    setUp = RepairFixtureTests.setUp
    put = RepairFixtureTests.put

    def test_relative_link_rejected_before_hashing_traversal_and_exclusion(self):
        for member, directory in [('Lib/observed-link', True),
                                  ('Lib/site-packages', True),
                                  ('Lib/observed-file', False)]:
            with self.subTest(member=member):
                tree = self.root / member.rsplit('/', 1)[1]
                target = tree / member
                payload = target / 'unread.txt' if directory else target
                payload.parent.mkdir(parents=True)
                payload.write_bytes(b'inert fixture; never read by inventory')
                records = tree / 'records'
                records.mkdir()
                real_is_symlink = Path.is_symlink
                def is_symlink(path):
                    return path == target or real_is_symlink(path)
                # Only the named ordinary fixture emulates a link. Keep real walking.
                with mock.patch.object(Path, 'is_symlink', is_symlink), \
                        mock.patch.object(buildlib.os, 'scandir', wraps=os.scandir) as scan, \
                        mock.patch.object(buildlib.os, 'walk', wraps=os.walk) as walk, \
                        mock.patch.object(Path, 'resolve', side_effect=AssertionError('resolve link')) as resolve, \
                        mock.patch.object(Path, 'readlink', side_effect=AssertionError('read link target')) as readlink, \
                        mock.patch.object(buildlib, 'file_hash', side_effect=AssertionError('hash link')) as hashed:
                    with self.assertRaises(ValueError) as caught:
                        self.build.snapshot_roots({'bootstrap': tree}, records)
                    hashed.assert_not_called()
                    resolve.assert_not_called()
                    readlink.assert_not_called()
                    walk.assert_called_once_with(tree, onerror=mock.ANY)
                    self.assertEqual([Path(c.args[0]) for c in scan.call_args_list], [tree, tree / 'Lib'])
                    self.assertEqual(str(caught.exception), 'Unexpected filesystem link: ' + repr(member))
                self.assertEqual(list(records.iterdir()), [])

    def test_link_diagnostic_escapes_and_bounds_only_lexical_relative_text(self):
        # Lexical-only names allow control/long-name checks without creating invalid Windows files.
        cases = [('link\n\x1b\u202e\u00e9', "'link\\n\\x1b\\u202e\\xe9'"),
                 ('x' * 512 + 'omitted-suffix', "'" + 'x' * 512 + "' [truncated]")]
        for member, expected in cases:
            with self.subTest(case='long' if len(member) > 512 else 'escaped'):
                target = self.root / member
                with mock.patch.object(buildlib.os, 'walk', return_value=[(str(self.root), [], [member])]), \
                        mock.patch.object(Path, 'is_symlink', lambda path: path == target), \
                        mock.patch.object(Path, 'resolve', side_effect=AssertionError('resolve link')), \
                        mock.patch.object(Path, 'readlink', side_effect=AssertionError('read link target')), \
                        mock.patch.object(buildlib, 'file_hash', side_effect=AssertionError('hash link')) as hashed:
                    with self.assertRaises(ValueError) as caught:
                        buildlib.inventory(self.root, exclude_dirs=('site-packages',))
                    hashed.assert_not_called()
                message = str(caught.exception)
                self.assertEqual(message, 'Unexpected filesystem link: ' + expected)
                self.assertTrue(message.isascii())
                self.assertLessEqual(len(message), 6200)
                self.assertNotIn(str(self.root), message)
                self.assertFalse(any(ord(c) < 32 or ord(c) == 127 for c in message))

    def test_root_link_diagnostic_uses_dot_without_walking_or_hashing(self):
        with mock.patch.object(Path, 'is_symlink', lambda path: path == self.root), \
                mock.patch.object(buildlib.os, 'walk') as walk, \
                mock.patch.object(buildlib, 'file_hash') as hashed:
            with self.assertRaises(ValueError) as caught:
                buildlib.inventory(self.root)
            walk.assert_not_called()
            hashed.assert_not_called()
        self.assertEqual(str(caught.exception), "Inventory root must be a real directory: '.'")


class BootstrapAliasTests(unittest.TestCase):
    """Owned inert python.exe; metadata/readlink seams are NOT hosted proof."""
    setUp = RepairFixtureTests.setUp
    put = RepairFixtureTests.put
    PAYLOAD = b'owned ordinary bootstrap fixture; never execute this file'

    def fixture(self):
        executable = self.put('bootstrap/python.exe', self.PAYLOAD)
        self.put('bootstrap/Lib/os.py', b'inert stdlib fixture')
        alias = self.put('bootstrap/python3.exe', b'emulated link object; not target bytes')
        records = self.root / 'records'
        records.mkdir()
        return executable.parent, executable, alias, records

    def links(self, targets, *, attributes=None):
        from contextlib import ExitStack
        from types import SimpleNamespace
        stack = ExitStack()
        original_lstat = Path.lstat
        original_readlink = os.readlink
        def lstat(path, *args, **kwargs):
            value = original_lstat(path, *args, **kwargs)
            values = {n: getattr(value, n) for n in dir(value) if n.startswith('st_')}
            if path in targets:
                values.update(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0x400,
                              st_reparse_tag=stat.IO_REPARSE_TAG_SYMLINK)
            values.update((attributes or {}).get(path, {}))
            return SimpleNamespace(**values)
        def readlink(path, *args, **kwargs):
            if Path(path) in targets:
                return targets[Path(path)]
            return original_readlink(path, *args, **kwargs)
        stack.enter_context(mock.patch.object(Path, 'lstat', lstat))
        stack.enter_context(mock.patch.object(os, 'readlink', readlink))
        return stack

    def snapshot(self, tree, executable, records, **kwargs):
        with mock.patch.object(self.build.sys, 'executable', str(executable)):
            return self.build.snapshot_roots({'bootstrap': tree}, records, **kwargs)

    def test_checked_alias_snapshot_and_export(self):
        tree, executable, alias, records = self.fixture()
        with self.links({alias: 'python.exe'}), \
                mock.patch.object(self.build.sys, 'executable', str(executable)), \
                mock.patch.object(self.build, 'run', side_effect=AssertionError('no fixture execution')):
            maps = self.build.snapshot_roots({'bootstrap': tree}, records)
            files = maps['bootstrap']['files']
            proof = files['python3.exe']
            self.assertEqual(proof['classification'], 'selected-bootstrap-file-symlink')
            self.assertEqual(proof['raw_target'], 'python.exe')
            self.assertEqual(proof['resolved_relative_target'], 'python.exe')
            self.assertEqual(proof['sha256'], buildlib.digest(self.PAYLOAD))
            self.assertEqual(proof['sha256'], files['python.exe'])
            self.assertEqual(proof['target_identity']['ino'], executable.lstat().st_ino)
            self.assertEqual(proof['target_identity']['dev'], executable.lstat().st_dev)
            self.assertEqual(proof['link_identity']['ino'], alias.lstat().st_ino)
            self.assertEqual(proof['selected_executable'], str(executable))
            self.assertEqual(set(files), {'python.exe', 'python3.exe', 'Lib/os.py'})
            initial_bytes = (records / 'input-bootstrap.json').read_bytes()
            self.assertEqual(json.loads(initial_bytes), maps['bootstrap'])
            self.assertEqual(self.build.snapshot_roots({'bootstrap': tree}, records, expected=maps), maps)
            self.build.verify_roots(maps)
            artifact = self.root / 'artifact'
            artifact.mkdir()
            buildlib.export_recipe(ROOT, artifact / 'recipe', buildlib.recipe_inventory(ROOT))
            self.build.recorded_pipeline(records, lambda: artifact)
            self.assertEqual((artifact / 'records/input-bootstrap.json').read_bytes(), initial_bytes)
            manifest = json.loads((artifact / 'manifest.json').read_bytes())
            self.assertEqual(manifest['files']['records/input-bootstrap.json'], buildlib.digest(initial_bytes))
            self.assertFalse((artifact / 'python3.exe').exists())

    def test_default_inventory_still_rejects_exact_alias_before_read(self):
        tree, executable, alias, records = self.fixture()
        with self.links({alias: 'python.exe'}), \
                mock.patch.object(os, 'readlink') as readlink, \
                mock.patch.object(buildlib, 'file_hash') as hashed:
            for operation in (lambda: buildlib.inventory(tree),
                              lambda: buildlib.verify_inventory(tree, {}),
                              lambda: buildlib.recipe_inventory(tree),
                              lambda: self.build.snapshot_roots({'dependency': tree}, records)):
                with self.assertRaisesRegex(ValueError, 'Unexpected filesystem link'):
                    operation()
            readlink.assert_not_called()
            hashed.assert_not_called()
        self.assertEqual(list(records.iterdir()), [])

    def test_other_names_nested_and_excluded_links_reject_before_target_read(self):
        for name in ('python3.11.exe', 'python3.14.exe', 'pythonw.exe',
                     'unlisted.exe', 'Lib/python3.exe', 'Lib/site-packages'):
            with self.subTest(name=name):
                base = self.root / name.replace('/', '-')
                executable = base / 'python.exe'
                executable.parent.mkdir()
                executable.write_bytes(self.PAYLOAD)
                link = base / name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.write_bytes(b'inert link fixture')
                with self.links({link: 'python.exe'}), \
                        mock.patch.object(os, 'readlink') as readlink, \
                        mock.patch.object(buildlib, 'file_hash', wraps=buildlib.file_hash) as hashed:
                    with self.assertRaisesRegex(ValueError, 'Unexpected filesystem link'):
                        buildlib.inventory(base, exclude_dirs=('site-packages',),
                                           bootstrap_executable=executable)
                    readlink.assert_not_called()
                    self.assertNotIn(link, [Path(c.args[0]) for c in hashed.call_args_list])

    def test_wrong_external_dangling_loop_and_chained_raw_targets(self):
        tree, executable, alias, records = self.fixture()
        outside = self.put('outside/python.exe', b'not selected')
        other = self.put('bootstrap/other.exe', b'ordinary wrong target')
        for raw in ('other.exe', str(outside), '../outside/python.exe', 'absent.exe',
                    'python3.exe', 'chain.exe', 'Lib/../python.exe', './python.exe'):
            with self.subTest(raw=raw), self.links({alias: raw}), \
                    mock.patch.object(buildlib, 'file_hash') as hashed:
                with self.assertRaisesRegex(ValueError, 'Bootstrap alias rejected') as caught:
                    buildlib.inventory(tree, bootstrap_executable=executable)
                self.assertIn(ascii(raw), str(caught.exception))
                hashed.assert_not_called()
        self.assertEqual(outside.read_bytes(), b'not selected')
        self.assertEqual(other.read_bytes(), b'ordinary wrong target')

    def test_target_must_be_ordinary_present_and_unlinked(self):
        tree, executable, alias, records = self.fixture()
        for kind in ('linked', 'junction', 'directory', 'hardlinked', 'absent'):
            with self.subTest(kind=kind):
                links = {alias: 'python.exe'}
                attributes = {}
                if kind == 'linked':
                    links[executable] = 'other.exe'
                elif kind == 'junction':
                    attributes[executable] = {'st_file_attributes': 0x400,
                                              'st_reparse_tag': stat.IO_REPARSE_TAG_MOUNT_POINT}
                elif kind == 'directory':
                    attributes[executable] = {'st_mode': stat.S_IFDIR | 0o755}
                elif kind == 'hardlinked':
                    attributes[executable] = {'st_nlink': 2}
                else:
                    executable.unlink()
                try:
                    with self.links(links, attributes=attributes), \
                            mock.patch.object(buildlib, 'file_hash') as hashed:
                        with self.assertRaises((ValueError, OSError)):
                            buildlib.inventory(tree, bootstrap_executable=executable)
                        hashed.assert_not_called()
                finally:
                    if kind == 'absent':
                        executable.write_bytes(self.PAYLOAD)

    def test_candidate_must_be_file_symlink_not_directory_or_unknown_reparse(self):
        tree, executable, alias, records = self.fixture()
        for metadata in ({'st_file_attributes': 0x410},
                         {'st_reparse_tag': stat.IO_REPARSE_TAG_MOUNT_POINT},
                         {'st_reparse_tag': 0}, {'st_mode': stat.S_IFREG | 0o644}):
            with self.subTest(metadata=metadata), \
                    self.links({alias: 'python.exe'}, attributes={alias: metadata}), \
                    mock.patch.object(os, 'readlink') as readlink, \
                    mock.patch.object(buildlib, 'file_hash') as hashed:
                with self.assertRaises(ValueError):
                    buildlib.inventory(tree, bootstrap_executable=executable)
                readlink.assert_not_called()
                hashed.assert_not_called()

    def test_root_ancestor_and_child_reparse_never_traversed(self):
        tree, executable, alias, records = self.fixture()
        child = tree / 'Lib'
        for path in (tree.parent, tree, child):
            with self.subTest(path=path.name), \
                    self.links({alias: 'python.exe'}, attributes={path: {'st_file_attributes': 0x400}}), \
                    mock.patch.object(os, 'scandir', wraps=os.scandir) as scan, \
                    mock.patch.object(os, 'readlink') as readlink, \
                    mock.patch.object(buildlib, 'file_hash') as hashed:
                with self.assertRaises(ValueError):
                    buildlib.inventory(tree, bootstrap_executable=executable)
                self.assertNotIn(child, [Path(c.args[0]) for c in scan.call_args_list])
                readlink.assert_not_called()
                hashed.assert_not_called()

    def test_selected_executor_must_be_exact_target_not_equal_bytes_elsewhere(self):
        tree, executable, alias, records = self.fixture()
        other = self.put('other/python.exe', self.PAYLOAD)
        for selected in (other, alias, tree / 'absent.exe'):
            with self.subTest(selected=selected.name), self.links({alias: 'python.exe'}), \
                    mock.patch.object(buildlib, 'file_hash') as hashed:
                with self.assertRaisesRegex(ValueError, 'Bootstrap alias rejected'):
                    buildlib.inventory(tree, bootstrap_executable=selected)
                hashed.assert_not_called()

    def test_absolute_target_preserves_actual_raw_spelling(self):
        tree, executable, alias, records = self.fixture()
        values = [str(executable)]
        if os.name == 'nt':
            values.append('\\\\?\\' + str(executable))
        for raw in values:
            with self.subTest(raw=raw), self.links({alias: raw}):
                files = buildlib.inventory(tree, bootstrap_executable=executable)
                self.assertEqual(files['python3.exe']['raw_target'], raw)
                self.assertEqual(files['python3.exe']['resolved_relative_target'], 'python.exe')

    def test_missing_alias_and_no_alias_initial_state_are_compared(self):
        tree, executable, alias, records = self.fixture()
        with self.links({alias: 'python.exe'}):
            maps = self.snapshot(tree, executable, records)
        alias.unlink()
        with mock.patch.object(self.build.sys, 'executable', str(executable)):
            with self.assertRaisesRegex(RuntimeError, 'Toolchain input tree changed'):
                self.build.verify_roots(maps)
            with self.assertRaisesRegex(RuntimeError, 'Toolchain input tree changed'):
                self.build.snapshot_roots({'bootstrap': tree}, records, expected=maps)
            self.assertEqual(json.loads((records / 'input-bootstrap.json').read_bytes()), maps['bootstrap'])
            absent = self.build.snapshot_roots({'bootstrap': tree}, records)
            self.assertNotIn('python3.exe', absent['bootstrap']['files'])
            alias.write_bytes(b'emulated new alias')
            with self.links({alias: 'python.exe'}), self.assertRaises(RuntimeError):
                self.build.verify_roots(absent)

    def test_revalidation_detects_raw_identity_content_and_type_drift(self):
        tree, executable, alias, records = self.fixture()
        with self.links({alias: 'python.exe'}):
            maps = self.snapshot(tree, executable, records)
        saved = (records / 'input-bootstrap.json').read_bytes()
        for kind in ('raw', 'link-identity', 'target-identity', 'content', 'ordinary-alias'):
            with self.subTest(kind=kind):
                links = {alias: str(executable) if kind == 'raw' else 'python.exe'}
                attributes = {}
                if kind == 'link-identity':
                    attributes[alias] = {'st_ino': alias.lstat().st_ino + 1}
                elif kind == 'target-identity':
                    attributes[executable] = {'st_ino': executable.lstat().st_ino + 1}
                elif kind == 'content':
                    executable.write_bytes(b'changed inert target')
                elif kind == 'ordinary-alias':
                    links = {}
                with self.links(links, attributes=attributes), \
                        mock.patch.object(self.build.sys, 'executable', str(executable)):
                    with self.assertRaises(RuntimeError):
                        self.build.verify_roots(maps)
                    with self.assertRaises(RuntimeError):
                        self.build.snapshot_roots({'bootstrap': tree}, records, expected=maps)
                self.assertEqual((records / 'input-bootstrap.json').read_bytes(), saved)
                if kind == 'content':
                    executable.write_bytes(self.PAYLOAD)

    def test_target_read_never_opens_alias_and_detects_during_hash_drift(self):
        tree, executable, alias, records = self.fixture()
        real_hash = buildlib.file_hash
        reads = []
        targets = {alias: 'python.exe'}
        def hashed(path):
            reads.append(Path(path))
            self.assertNotEqual(Path(path), alias)
            value = real_hash(path)
            if Path(path) == executable:
                targets[alias] = 'wrong.exe'
            return value
        with self.links(targets), mock.patch.object(buildlib, 'file_hash', side_effect=hashed):
            with self.assertRaises(ValueError):
                buildlib.inventory(tree, bootstrap_executable=executable)
        self.assertIn(executable, reads)
        self.assertNotIn(alias, reads)

    def test_failure_records_preserve_meaningful_rejected_target(self):
        tree, executable, alias, records = self.fixture()
        with self.links({alias: 'wrong.exe'}):
            with self.assertRaisesRegex(ValueError, "raw_target='wrong.exe'"):
                self.build.recorded_pipeline(records, lambda: self.snapshot(tree, executable, records))
        self.assertEqual(json.loads((records / 'status.json').read_bytes())['state'], 'failed')
        self.assertFalse((records / 'input-bootstrap.json').exists())
        self.assertTrue((records / 'manifest.json').exists())

    def test_real_owned_physical_alias_when_available(self):
        tree, executable, alias, records = self.fixture()
        alias.unlink()
        try:
            alias.symlink_to('python.exe')
        except OSError as exc:
            self.skipTest('Physical owned alias unavailable: ' + type(exc).__name__)
        with mock.patch.object(self.build.sys, 'executable', str(executable)):
            maps = self.build.snapshot_roots({'bootstrap': tree}, records)
            self.build.verify_roots(maps)
            self.assertEqual(maps['bootstrap']['files']['python3.exe']['sha256'], buildlib.digest(self.PAYLOAD))

    def test_ambiguous_absolute_spellings_and_nonordinary_link_identity(self):
        tree, executable, alias, records = self.fixture()
        for raw in (str(tree) + os.sep + '.' + os.sep + 'python.exe',
                    str(tree) + os.sep * 2 + 'python.exe'):
            with self.subTest(raw=raw), self.links({alias: raw}), \
                    mock.patch.object(buildlib, 'file_hash') as hashed:
                with self.assertRaises(ValueError):
                    buildlib.inventory(tree, bootstrap_executable=executable)
                hashed.assert_not_called()
        for metadata in ({'st_nlink': 2}, {'st_ino': 0}):
            with self.subTest(metadata=metadata), \
                    self.links({alias: 'python.exe'}, attributes={alias: metadata}), \
                    mock.patch.object(os, 'readlink') as readlink, \
                    mock.patch.object(buildlib, 'file_hash') as hashed:
                with self.assertRaises(ValueError):
                    buildlib.inventory(tree, bootstrap_executable=executable)
                readlink.assert_not_called()
                hashed.assert_not_called()

    def test_directory_candidate_and_both_ends_of_loop_are_rejected(self):
        tree, executable, alias, records = self.fixture()
        alias.unlink()
        alias.mkdir()
        with self.links({alias: 'python.exe'}), \
                mock.patch.object(os, 'readlink') as readlink, \
                mock.patch.object(buildlib, 'file_hash') as hashed:
            with self.assertRaisesRegex(ValueError, 'Bootstrap alias rejected: python3.exe; directory entry'):
                buildlib.inventory(tree, bootstrap_executable=executable)
            readlink.assert_not_called()
            hashed.assert_not_called()
        alias.rmdir()
        alias.write_bytes(b'emulated loop alias')
        with self.links({alias: 'python.exe', executable: 'python3.exe'}), \
                mock.patch.object(os, 'readlink') as readlink, \
                mock.patch.object(buildlib, 'file_hash') as hashed:
            with self.assertRaisesRegex(ValueError, 'Unexpected filesystem link'):
                buildlib.inventory(tree, bootstrap_executable=executable)
            readlink.assert_not_called()
            hashed.assert_not_called()

    def test_snapshot_preserves_ordinary_exclusion_and_rejects_unlisted_link(self):
        tree, executable, alias, records = self.fixture()
        self.put('bootstrap/Lib/site-packages/not-consumed.txt', b'ordinary excluded fixture')
        with self.links({alias: 'python.exe'}):
            maps = self.snapshot(tree, executable, records)
        self.assertEqual(set(maps['bootstrap']['files']), {'python.exe', 'python3.exe', 'Lib/os.py'})
        saved = (records / 'input-bootstrap.json').read_bytes()
        unknown = self.put('bootstrap/unlisted.exe', b'emulated unlisted symlink')
        with self.links({alias: 'python.exe', unknown: 'python.exe'}), \
                mock.patch.object(self.build.sys, 'executable', str(executable)), \
                mock.patch.object(os, 'readlink') as readlink, \
                mock.patch.object(buildlib, 'file_hash') as hashed:
            with self.assertRaises(ValueError):
                self.build.verify_roots(maps)
            readlink.assert_not_called()
            hashed.assert_not_called()
        self.assertEqual((records / 'input-bootstrap.json').read_bytes(), saved)

    def test_target_changes_during_hash_and_selected_executor_drift(self):
        tree, executable, alias, records = self.fixture()
        with self.links({alias: 'python.exe'}):
            maps = self.snapshot(tree, executable, records)
        other = self.put('elsewhere/python.exe', self.PAYLOAD)
        with self.links({alias: 'python.exe'}), mock.patch.object(self.build.sys, 'executable', str(other)):
            with self.assertRaises(ValueError):
                self.build.verify_roots(maps)
        original_hash = buildlib.file_hash
        def changed(path):
            value = original_hash(path)
            if Path(path) == executable:
                executable.write_bytes(b'changed while reading inventory')
            return value
        with self.links({alias: 'python.exe'}), mock.patch.object(buildlib, 'file_hash', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during inventory'):
                buildlib.inventory(tree, bootstrap_executable=executable)

    def test_initial_binding_survives_toolchain_snapshot_and_final_verification_wiring(self):
        tree = ast.parse((ROOT / 'scripts/build.py').read_text(encoding='utf-8'))
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        body = functions['perform_build']
        text = ast.unparse(body)
        self.assertIn("bootstrap_inputs = snapshot_roots({'bootstrap': Path(sys.base_prefix)}, records)", text)
        self.assertLess(text.index('bootstrap_inputs ='), text.index('download('))
        self.assertIn('toolchain(work, records, bootstrap_inputs)', text)
        self.assertIn('snapshot_roots(roots, records, expected=bootstrap_inputs)',
                      ast.unparse(functions['toolchain']))
        self.assertLess(text.index('verify_roots(bootstrap_inputs)'), text.index("ROOT / 'scripts/verify_source.py'"))
        self.assertLess(text.index('verify_roots(input_maps)'), text.index('run(command,'))
        self.assertGreater(text.rindex('verify_roots(bootstrap_inputs)'), text.index('run(command,'))
        self.assertLess(text.rindex('verify_roots(bootstrap_inputs)'), text.index('make_package('))
        self.assertGreater(text.rindex('verify_roots(input_maps)'), text.index("records / 'audit-gate.json'"))
        self.assertIn('inventory(source)', text)


class NativeTrackingLogTests(unittest.TestCase):
    """Observed MSBuild paths; owned synthetic text, NOT exported native bytes."""
    setUp = RepairFixtureTests.setUp
    put = RepairFixtureTests.put

    def fixture(self, tag='fixture'):
        work = self.root / tag / 'work'
        records = self.root / tag / 'records'
        records.mkdir(parents=True)
        expected_logs, expected_inputs = {}, {}
        names = ('CL.command.1.tlog', 'CL.read.1.tlog', 'CL.write.1.tlog',
                 'Cl.items.tlog', 'link.command.1.tlog', 'link.read.1.tlog',
                 'link.secondary.1.tlog', 'link.write.1.tlog', 'rc.command.1.tlog',
                 'rc.read.1.tlog', 'rc.write.1.tlog')
        for project in ('_asyncio', '_bz2'):
            inputs = {}
            for tool in ('CL', 'link', 'rc'):
                file = self.put(tag + '/inputs/' + project + '/' + tool + '.h',
                                ('owned inert ' + project + ' ' + tool + ' input').encode())
                inputs[tool] = file
                expected_inputs[str(file)] = buildlib.file_hash(file)
            for index, name in enumerate(names):
                # This PID-bearing write-log filename is in the verified manifest.
                if project == '_bz2' and name == 'CL.write.1.tlog':
                    name = 'CL.4596.write.1.tlog'
                relative = '314amd64_Release/' + project + '/' + project + '.tlog/' + name
                if '.read.' in name:
                    text = '^owned-source.c\n\n' + str(inputs[name.split('.')[0]]) + '\n'
                elif name == 'CL.command.1.tlog':
                    text = '^owned-source.c\n/D NDEBUG /c owned-source.c\n'
                else:
                    text = '^owned-source.c\nowned synthetic ' + project + ' ' + name + '\n'
                encoding = ('utf-16', 'utf-8-sig', 'utf-8', 'utf-16-be')[index % 4]
                data = text.encode(encoding)
                if encoding == 'utf-16-be':
                    data = b'\xfe\xff' + data
                file = work / 'obj' / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(data)
                expected_logs[relative] = data
        return work, records, expected_logs, expected_inputs

    def assert_no_success(self, records):
        self.assertFalse((records / 'native-read-inputs.json').exists())
        self.assertFalse((records / 'compiler-configuration.json').exists())

    def test_observed_nested_layout_complete_relative_copies_and_input_hashes(self):
        work, records, expected_logs, expected_inputs = self.fixture()
        before = buildlib.inventory(work)
        reads = []
        real_read = Path.read_bytes
        def read(path):
            if path.is_relative_to(work / 'obj'):
                reads.append(path.relative_to(work / 'obj').as_posix())
            return real_read(path)
        with mock.patch.object(Path, 'read_bytes', read):
            self.build.native_inputs(work, records)
        self.assertEqual(reads, sorted(expected_logs, key=Path))
        self.assertEqual(buildlib.inventory(records / 'native-logs'),
                         {name: buildlib.digest(data) for name, data in expected_logs.items()})
        for name, data in expected_logs.items():
            self.assertEqual((records / 'native-logs' / name).read_bytes(), data)
        self.assertEqual(json.loads((records / 'native-read-inputs.json').read_bytes()), expected_inputs)
        self.assertEqual(json.loads((records / 'compiler-configuration.json').read_bytes()), {
            'cl_command_files': 2, 'UseTIER2': '0', 'UseJIT': 'false',
            'tier2_or_jit_definitions_found': False})
        self.assertEqual(buildlib.inventory(work), before)

    def test_empty_tlog_containers_and_ordinary_subdirectories_preserve_completeness(self):
        work, records, expected_logs, expected_inputs = self.fixture()
        (work / 'obj/empty.tlog/CL.command.empty.tlog').mkdir(parents=True)
        extra = work / 'obj/ordinary/deeper/extra.TLOG'
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b'owned synthetic additional tracking log\n')
        (extra.parent / 'ignored.txt').write_bytes(b'owned non-log\n')
        expected_logs[extra.relative_to(work / 'obj').as_posix()] = extra.read_bytes()
        self.build.native_inputs(work, records)
        self.assertEqual(buildlib.inventory(records / 'native-logs'),
                         {name: buildlib.digest(data) for name, data in expected_logs.items()})
        self.assertEqual(json.loads((records / 'native-read-inputs.json').read_bytes()), expected_inputs)
        self.assertEqual(json.loads((records / 'compiler-configuration.json').read_bytes())['cl_command_files'], 2)

    def test_nested_compiler_definitions_reject_tier2_and_jit(self):
        for token in ('_Py_TIER2', '_Py_JIT'):
            with self.subTest(token=token):
                work, records, _, _ = self.fixture(token)
                command = work / 'obj/314amd64_Release/_bz2/_bz2.tlog/CL.command.1.tlog'
                command.write_bytes(('^owned-source.c\n/D ' + token + '=false\n').encode('utf-16'))
                with self.assertRaisesRegex(RuntimeError, 'Tier 2/JIT compiler definition detected'):
                    self.build.native_inputs(work, records)
                self.assert_no_success(records)

    def test_nested_read_logs_require_absolute_existing_files(self):
        for kind in ('relative', 'missing', 'directory'):
            with self.subTest(kind=kind):
                work, records, _, _ = self.fixture(kind)
                bad = {'relative': 'owned-relative.h', 'missing': str(work / 'missing.h'),
                       'directory': str(work / 'obj')}[kind]
                read = work / 'obj/314amd64_Release/_bz2/_bz2.tlog/link.read.1.tlog'
                read.write_bytes(('^owned-source.c\n' + bad + '\n').encode('utf-8-sig'))
                with self.assertRaisesRegex(RuntimeError, 'Unresolved native input from read tlog'):
                    self.build.native_inputs(work, records)
                self.assert_no_success(records)

    def test_missing_commands_or_read_inputs_fail_even_with_tlog_directories(self):
        for missing in ('commands', 'inputs'):
            with self.subTest(missing=missing):
                work, records, expected_logs, _ = self.fixture(missing)
                for name in expected_logs:
                    file = work / 'obj' / name
                    if missing == 'commands' and file.name.lower().startswith('cl.command.'):
                        file.unlink()
                        file.mkdir()  # A command-named container is not a command file.
                    elif missing == 'inputs' and '.read.' in file.name.lower():
                        file.write_bytes(b'^owned-source.c\n\n')
                with self.assertRaisesRegex(RuntimeError, 'Native input/compiler command tracking missing'):
                    self.build.native_inputs(work, records)
                self.assert_no_success(records)

    def test_malformed_nested_log_encoding_is_not_ignored(self):
        for tag, data in (('utf8', b'\x80'), ('utf16', b'\xff\xfe\x00')):
            with self.subTest(encoding=tag):
                work, records, _, _ = self.fixture(tag)
                (work / 'obj/314amd64_Release/_asyncio/_asyncio.tlog/Cl.items.tlog').write_bytes(data)
                with self.assertRaises(UnicodeError):
                    self.build.native_inputs(work, records)
                self.assert_no_success(records)

    def test_metadata_and_enumeration_errors_are_not_silently_omitted(self):
        relatives = ('', '314amd64_Release/_asyncio',
                     '314amd64_Release/_asyncio/_asyncio.tlog',
                     '314amd64_Release/_asyncio/_asyncio.tlog/CL.read.1.tlog')
        for operation in ('lstat', 'iterdir'):
            for index, relative in enumerate(relatives if operation == 'lstat' else relatives[:-1]):
                with self.subTest(operation=operation, relative=relative):
                    work, records, _, _ = self.fixture(operation + str(index))
                    target = work / 'obj' / relative
                    original = getattr(Path, operation)
                    seen = []
                    def denied(path, *args, **kwargs):
                        if path == target:
                            seen.append(path)
                            raise PermissionError('owned metadata/enumeration denial')
                        return original(path, *args, **kwargs)
                    with mock.patch.object(Path, operation, denied):
                        with self.assertRaisesRegex(PermissionError, 'owned metadata/enumeration denial'):
                            self.build.native_inputs(work, records)
                    self.assertEqual(seen, [target])
                    self.assert_no_success(records)

    def test_native_log_read_and_copy_failures_propagate(self):
        for operation in ('read_bytes', 'write_bytes'):
            with self.subTest(operation=operation):
                work, records, _, _ = self.fixture(operation)
                relative = '314amd64_Release/_asyncio/_asyncio.tlog/CL.command.1.tlog'
                target = (work / 'obj' if operation == 'read_bytes' else records / 'native-logs') / relative
                original = getattr(Path, operation)
                seen = []
                def denied(path, *args, **kwargs):
                    if path == target:
                        seen.append(path)
                        raise PermissionError('owned native log IO denial')
                    return original(path, *args, **kwargs)
                with mock.patch.object(Path, operation, denied):
                    with self.assertRaisesRegex(PermissionError, 'owned native log IO denial'):
                        self.build.native_inputs(work, records)
                self.assertEqual(seen, [target])
                self.assert_no_success(records)

    def test_link_reparse_and_unknown_metadata_reject_before_traversal_or_read(self):
        from types import SimpleNamespace
        relatives = ('', '314amd64_Release/_asyncio',
                     '314amd64_Release/_asyncio/_asyncio.tlog',
                     '314amd64_Release/_asyncio/_asyncio.tlog/CL.command.1.tlog')
        cases = ({'st_mode': stat.S_IFLNK | 0o777},
                 {'st_file_attributes': stat.FILE_ATTRIBUTE_REPARSE_POINT},
                 {'st_reparse_tag': stat.IO_REPARSE_TAG_MOUNT_POINT},
                 {'st_mode': stat.S_IFIFO | 0o600},
                 {'st_mode': stat.S_IFCHR | 0o600}, {'st_mode': 0})
        for index, relative in enumerate(relatives):
            for variant, changed in enumerate(cases):
                with self.subTest(relative=relative, metadata=changed):
                    work, records, _, _ = self.fixture(str(index) + '-' + str(variant))
                    target = work / 'obj' / relative
                    lstat, iterdir, read = Path.lstat, Path.iterdir, Path.read_bytes
                    def metadata(path, *args, **kwargs):
                        info = lstat(path, *args, **kwargs)
                        if path == target:
                            values = {n: getattr(info, n) for n in dir(info) if n.startswith('st_')}
                            values.update(changed)
                            return SimpleNamespace(**values)
                        return info
                    def scan(path):
                        self.assertNotEqual(path, target, 'must reject before traversal')
                        return iterdir(path)
                    def guarded_read(path):
                        self.assertNotEqual(path, target, 'must reject before reading')
                        return read(path)
                    with mock.patch.object(Path, 'lstat', metadata), \
                            mock.patch.object(Path, 'iterdir', scan), \
                            mock.patch.object(Path, 'read_bytes', guarded_read):
                        with self.assertRaisesRegex(ValueError, 'Unexpected native tracking-log filesystem type'):
                            self.build.native_inputs(work, records)
                    self.assert_no_success(records)

    def test_real_hardlinked_tracking_file_is_rejected(self):
        work, records, _, _ = self.fixture()
        target = work / 'obj/314amd64_Release/_asyncio/_asyncio.tlog/CL.command.1.tlog'
        alias = self.root / 'owned-hardlink'
        alias.hardlink_to(target)
        self.assertEqual(target.lstat().st_nlink, 2)
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('must reject before reading')):
            with self.assertRaisesRegex(ValueError, 'Unexpected native tracking-log filesystem type'):
                self.build.native_inputs(work, records)
        self.assert_no_success(records)
        self.assertEqual(target.read_bytes(), alias.read_bytes())

    def test_real_symlink_files_and_containers_rejected_when_available(self):
        relatives = ('', '314amd64_Release/_asyncio',
                     '314amd64_Release/_asyncio/_asyncio.tlog',
                     '314amd64_Release/_asyncio/_asyncio.tlog/CL.command.1.tlog')
        for index, relative in enumerate(relatives):
            with self.subTest(relative=relative):
                work, records, _, _ = self.fixture(str(index))
                target = work / 'obj' / relative
                saved = self.root / ('owned-link-target-' + str(index))
                directory = target.is_dir()
                target.rename(saved)
                try:
                    target.symlink_to(saved, target_is_directory=directory)
                except OSError as exc:
                    saved.rename(target)
                    self.skipTest('Physical native-log symlink unavailable: ' + type(exc).__name__)
                try:
                    before = buildlib.inventory(saved) if directory else saved.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'Unexpected native tracking-log filesystem type'):
                        self.build.native_inputs(work, records)
                    self.assert_no_success(records)
                    self.assertEqual(before, buildlib.inventory(saved) if directory else saved.read_bytes())
                finally:
                    target.unlink()
                    saved.rename(target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--temp', type=Path, required=True)
    opts, remaining = parser.parse_known_args()
    SOURCE = opts.source.read_bytes()
    UPSTREAM = opts.source.resolve().parent.parent
    TEMP = opts.temp.resolve()
    TEMP.mkdir(parents=True, exist_ok=True)
    if hashlib.sha256(SOURCE).hexdigest() != buildlib.BEFORE:
        raise SystemExit('Test fixture is not the pinned original source')
    unittest.main(argv=[sys.argv[0], *remaining])
