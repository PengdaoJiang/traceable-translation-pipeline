"""Verify the extracted runtime in a disposable copy, without corpus or network."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe-only', action='store_true')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent / 'versioned_runtime'
    with tempfile.TemporaryDirectory(prefix='versioned-runtime-check-') as temporary:
        target = Path(temporary) / 'runtime'
        shutil.copytree(source, target, ignore=shutil.ignore_patterns('__pycache__', '*_RESULTS.json', '*.pyc'))
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location('runtime_platform', target / 'platform_api.py')
        platform = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = platform
        spec.loader.exec_module(platform)
        report = platform.probe(Path(temporary))
        print(json.dumps({'scope': 'current host and filesystem only', 'probe': report}), flush=True)
        missing = [key for key, value in report['capabilities'].items() if not value['available']]
        if args.probe_only:
            # Import and explicit rejection are useful even without strong primitives.
            if missing:
                try:
                    platform.probe(Path(temporary), required=missing)
                except platform.CapabilityUnavailable:
                    pass
                else:
                    raise AssertionError('Missing capabilities were silently accepted')
            return 0
        if missing:
            parser.error('Full suite requires these unavailable capabilities: ' + ', '.join(missing))
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
        commands = [
            [sys.executable, '-B', '-m', 'unittest', '-v', 'test_platform_api'],
            *[[sys.executable, '-B', name] for name in (
                'test_host_checkpoint.py', 'test_hot_gate.py',
                'test_core_platform_boundary.py', 'test_query_cache_policy.py')],
        ]
        for command in commands:
            subprocess.run(command, cwd=target, env=env, check=True, timeout=180)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
