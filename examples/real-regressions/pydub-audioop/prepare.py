"""Prepare the known Pydub audioop regression without executing upstream code.

Usage from the TomorrowCI checkout:
  python examples/real-regressions/pydub-audioop/prepare.py SOURCE OUTPUT --mode before
  python examples/real-regressions/pydub-audioop/prepare.py SOURCE OTHER_OUTPUT --mode fixed

SOURCE must be a clean checkout of the exact upstream SHA below. OUTPUT must
not exist. Run TomorrowCI from OUTPUT/trial after preparation. The fixed lock
targets Linux x86_64 Python 3.14; it is not a portable distribution lock.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

CASE = Path(__file__).resolve().parent
sys.path.insert(0, str(CASE.parents[2] / 'scripts'))
import prepare_python_trial as trial

UPSTREAM = '103e339d3bc7a9a58a9f1de65f7d8074659b5f5a'


def prepare(source: Path, output: Path, mode: str) -> dict:
    source, output = source.resolve(strict=True), output.resolve()
    if output.exists() or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('Choose a new output directory outside the source checkout')
    if trial.git(source, 'rev-parse', '--show-prefix'):
        raise ValueError('Source must be the checkout root')
    if trial.git(source, 'rev-parse', 'HEAD') != UPSTREAM:
        raise ValueError('Source must be exactly ' + UPSTREAM)
    if trial.git(source, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise ValueError('Source must be clean')
    output.mkdir(parents=True)
    overlay = output / 'source'
    trial.git(source, 'clone', '--no-local', '--template=', '--', str(source), str(overlay))
    trial.git(overlay, 'checkout', '--detach', UPSTREAM)
    # Explicit fixture transformation, not a claim of symlink equivalence.
    # This directory link is unused by the fixed, ffmpeg-free test selection.
    if trial.git_bytes(overlay, 'show', UPSTREAM + ':test/pydub') != b'../pydub/':
        raise ValueError('Unexpected upstream directory link')
    trial.git(overlay, 'rm', '--', 'test/pydub')
    test_bytes = (CASE / 'test_audioop_compat.py').read_bytes()
    (overlay / 'test_audioop_compat.py').write_bytes(test_bytes)
    if mode == 'fixed':
        trial.git(overlay, 'apply', '--', str(CASE / 'fix.patch'))
    trial.git(overlay, 'add', '--', 'test_audioop_compat.py', 'setup.py')
    trial.git(overlay, '-c', 'user.name=TomorrowCI local regression',
              '-c', 'user.email=tomorrowci@example.invalid', 'commit',
              '-m', 'Prepare known Pydub regression: ' + mode)
    profile = trial.prepare(source=overlay, output=output / 'trial', baseline='3.11',
                            candidate='3.14', framework='unittest', source_root='.',
                            packages=['pydub'], test_args=['test_audioop_compat', '-v'],
                            stdlib_only=mode == 'before',
                            requirements=CASE / 'requirements.fixed.txt' if mode == 'fixed' else None)
    profile['regression_case'] = dict(upstream_sha=UPSTREAM, mode=mode,
        source_transformations=['Added fixed PCM regression assertions',
                                'Removed unused test/pydub directory link'],
        known_upstream_issue='https://github.com/jiaaro/pydub/issues/839',
        test_sha256=hashlib.sha256(test_bytes).hexdigest(),
        fix_patch_sha256=hashlib.sha256((CASE / 'fix.patch').read_bytes()).hexdigest() if mode == 'fixed' else None,
        scope='Eight focused PCM tests, not full upstream, codec or device qualification')
    (output / 'trial/.tomorrowci-trial-profile.json').write_text(
        json.dumps(profile, indent=2) + '\n', encoding='utf-8')
    return profile


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--mode', choices=['before', 'fixed'], required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output, args.mode), indent=2))
