"""Exercise publication gates without a signing certificate or Apple requests."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = "Developer ID Application: Release Test (G2RU5ZQR8P)"

MOCK = r'''#!/usr/bin/env python3
import json, os, shutil, sys, zipfile
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_LOG'], 'a') as log:
    log.write(json.dumps([name, *args]) + '\n')
if name == 'security':
    print('1) ABC "' + os.environ['MYCEL_SIGN_IDENTITY'] + '"')
elif name == 'cargo' and 'build' in args:
    app = Path(os.environ['MOCK_ROOT'])/'target/universal-apple-darwin/release/bundle/macos/Mycel.app'
    app.mkdir(parents=True)
    (app/'test-content').write_text('app')
elif name == 'xcrun':
    if args[:2] == ['notarytool', 'submit']:
        print(json.dumps({'id':'test-id', 'status':os.environ.get('MOCK_NOTARY_STATUS', 'Accepted')}))
    elif args[:2] == ['stapler', 'validate'] and os.environ.get('MOCK_STAPLER_FAIL'):
        sys.exit(1)
elif name == 'codesign' and '-dvvv' in args:
    print('Timestamp=Nov 17, 2026\nCodeDirectory flags=0x10000(runtime)', file=sys.stderr)
elif name == 'spctl':
    if os.environ.get('MOCK_MOUNTED_APP_FAIL') and '/Mycel.app' in args[-1] and '/image/' not in args[-1] and '/extracted/' not in args[-1]:
        sys.exit(1)
elif name == 'ditto':
    src, dst = map(Path, args[-2:])
    if '-c' in args:
        with zipfile.ZipFile(dst, 'w') as archive:
            for file in src.rglob('*'):
                if file.is_file(): archive.write(file, file.relative_to(src.parent))
    elif '-x' in args:
        with zipfile.ZipFile(src) as archive: archive.extractall(dst)
    else:
        shutil.copytree(src, dst, dirs_exist_ok=True)
elif name == 'hdiutil':
    if args[0] == 'create':
        Path(args[-1]).write_text(args[args.index('-srcfolder')+1])
    elif args[0] == 'attach':
        mount = Path(args[args.index('-mountpoint')+1])
        shutil.copytree(Path(Path(args[-1]).read_text())/'Mycel.app', mount/'Mycel.app')
    elif args[0] == 'detach':
        shutil.rmtree(Path(args[-1])/'Mycel.app')
'''

@unittest.skipUnless(sys.platform == 'darwin', 'Mac packaging uses Apple plutil')
class MacReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mycel-release-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ['scripts', 'apps/host/src-tauri', 'node_modules', 'bin']:
            (self.root/directory).mkdir(parents=True)
        for script in ['package-mac.sh', 'verify-mac.sh', 'remap-paths.sh']:
            shutil.copy2(ROOT/'scripts'/script, self.root/'scripts'/script)
        (self.root/'apps/host/src-tauri/tauri.conf.json').write_text('{\n  "version": "0.1.0"\n}\n')
        for name in ['cargo', 'rustup', 'security', 'xcrun', 'codesign', 'spctl', 'hdiutil', 'ditto']:
            path = self.root/'bin'/name
            path.write_text(MOCK)
            path.chmod(0o755)
        self.env = {k:v for k,v in os.environ.items() if not k.startswith(('MYCEL_', 'APPLE_', 'TAURI_'))}
        self.env.update(PATH=f"{self.root/'bin'}:{os.environ['PATH']}",
                        MOCK_ROOT=str(self.root), MOCK_LOG=str(self.root/'calls.jsonl'))

    def run_package(self, **env):
        return subprocess.run(['bash', str(self.root/'scripts/package-mac.sh'), '--universal'],
                              env={**self.env, **env}, capture_output=True, text=True)

    def assert_no_packages(self):
        self.assertEqual(list((self.root/'dist-release').glob('Mycel_*')), [])

    def test_missing_identity_stops_before_tools_or_files(self):
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('require MYCEL_SIGN_IDENTITY', result.stderr)
        self.assertFalse((self.root/'calls.jsonl').exists())
        self.assert_no_packages()

    def test_missing_notarization_stops_before_build(self):
        result = self.run_package(MYCEL_SIGN_IDENTITY=IDENTITY)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('require notarization credentials', result.stderr)
        self.assertFalse((self.root/'calls.jsonl').exists())
        self.assert_no_packages()

    def test_rejected_submission_exposes_no_downloads(self):
        result = self.run_package(MYCEL_SIGN_IDENTITY=IDENTITY, MYCEL_NOTARY_PROFILE='test', MOCK_NOTARY_STATUS='Invalid')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Invalid', result.stdout)
        self.assert_no_packages()
        self.assertEqual(list((self.root/'dist-release').glob('.mac-release.*')), [])

    def test_verified_containers_only_published_after_all_checks(self):
        result = self.run_package(MYCEL_SIGN_IDENTITY=IDENTITY, MYCEL_NOTARY_PROFILE='test')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        packages = sorted(p.name for p in (self.root/'dist-release').glob('Mycel_*'))
        self.assertEqual(packages, ['Mycel_0.1.0_universal_notarized.app.zip', 'Mycel_0.1.0_universal_notarized.dmg'])
        calls = [json.loads(line) for line in (self.root/'calls.jsonl').read_text().splitlines()]
        self.assertEqual(sum(c[:3] == ['xcrun', 'notarytool', 'submit'] for c in calls), 2)
        app_checks = [c[-1] for c in calls if c[0] == 'spctl' and 'execute' in c]
        self.assertEqual(len(app_checks), 3)  # staged, unzipped and mounted
        self.assertTrue(any('/extracted/Mycel.app' in p for p in app_checks))
        self.assertTrue(any(c[0] == 'hdiutil' and c[1] == 'detach' for c in calls))

    def test_gatekeeper_rejection_of_mounted_app_blocks_publication_and_detaches(self):
        result = self.run_package(MYCEL_SIGN_IDENTITY=IDENTITY, MYCEL_NOTARY_PROFILE='test', MOCK_MOUNTED_APP_FAIL='1')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_packages()
        calls = [json.loads(line) for line in (self.root/'calls.jsonl').read_text().splitlines()]
        self.assertTrue(any(c[0] == 'hdiutil' and c[1] == 'detach' for c in calls))

    def test_missing_staple_blocks_publication(self):
        result = self.run_package(MYCEL_SIGN_IDENTITY=IDENTITY, MYCEL_NOTARY_PROFILE='test', MOCK_STAPLER_FAIL='1')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_packages()

if __name__ == '__main__':
    unittest.main()
