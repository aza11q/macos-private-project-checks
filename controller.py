"""Public build instructions; private project data stays in encrypted results."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import urllib.request
import urllib.error
import urllib.parse
import zipfile

BUILD_ROOT = Path(os.environ['RUNNER_TEMP']) / 'native-private-build'
SOURCE = BUILD_ROOT / 'source'
LOGS = BUILD_ROOT / 'logs'
AGE = BUILD_ROOT / 'tools/age'
DIGESTS = {
    'arm64': ('arm64', 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'),
    'intel': ('amd64', '1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539'),
}


def logged(command, name, *, cwd=None, env=None):
    with (LOGS / name).open('ab') as stream:
        return subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT).returncode


def tools(architecture):
    target, expected = DIGESTS[architecture]
    url = f'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-{target}.tar.gz'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Encryption tool checksum differs')
    import io
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as packed:
        member = packed.getmember('age/age')
        if not member.isfile():
            raise ValueError('Unexpected encryption tool format')
        AGE.parent.mkdir(parents=True, exist_ok=True)
        AGE.write_bytes(packed.extractfile(member).read())
        AGE.chmod(0o755)


def checkout(commit):
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('An exact source commit is required')
    repository = os.environ['PRIVATE_SOURCE_REPO']
    if not re.fullmatch(r'git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git', repository):
        raise ValueError('Expected a GitHub SSH repository')
    key = BUILD_ROOT / 'temporary-readonly-key'
    key.write_bytes(base64.b64decode(os.environ['PRIVATE_SOURCE_KEY'], validate=True))
    key.chmod(0o600)
    known = BUILD_ROOT / 'known-hosts'
    try:
        request = urllib.request.Request('https://api.github.com/meta', headers={
            'Authorization': 'Bearer ' + os.environ['PUBLIC_METADATA_TOKEN'],
            'Accept': 'application/vnd.github+json', 'User-Agent': 'native-project-checks'})
        with urllib.request.urlopen(request, timeout=45) as response:
            host = json.load(response)
        known.write_text(''.join('github.com ' + k + '\n' for k in host['ssh_keys']), encoding='utf-8')
        env = {k: v for k, v in os.environ.items()
               if k not in ('PRIVATE_SOURCE_KEY', 'PRIVATE_SOURCE_REPO', 'PUBLIC_METADATA_TOKEN')}
        env['GIT_SSH_COMMAND'] = (f'ssh -i {shlex.quote(str(key))} -o IdentitiesOnly=yes -o BatchMode=yes '
            f'-o StrictHostKeyChecking=yes -o UserKnownHostsFile={shlex.quote(str(known))}')
        SOURCE.mkdir()
        commands = [(['git', 'init', str(SOURCE)], None),
                    (['git', 'remote', 'add', 'origin', repository], SOURCE),
                    (['git', 'fetch', '--depth', '1', 'origin', commit], SOURCE),
                    (['git', 'checkout', '--detach', 'FETCH_HEAD'], SOURCE)]
        for command, cwd in commands:
            if logged(command, 'checkout.log', cwd=cwd, env=env):
                raise RuntimeError('Private checkout failed')
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, env=env, text=True).strip()
        if actual != commit:
            raise ValueError('Source revision differs')
        (LOGS / 'source-commit.txt').write_text(actual, encoding='utf-8')
    finally:
        key.unlink(missing_ok=True)


def source_path(name):
    path = (SOURCE / name).resolve()
    if not path.is_relative_to(SOURCE.resolve()):
        raise ValueError('Requested path leaves the private source')
    return path


def install():
    requirement = source_path(os.environ['PRIVATE_REQUIREMENTS'])
    command = ['python', '-m', 'pip', 'install', '-r', str(requirement)]
    links = os.environ.get('PRIVATE_WHEEL_LINKS')
    if links:
        command += ['--find-links', str(source_path(links))]
    return logged(command, 'dependencies.log', cwd=SOURCE)


def run_private():
    command = json.loads(os.environ['PRIVATE_COMMAND'])
    if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
        raise ValueError('Private command must be a JSON argument list')
    result = logged(command, 'private-command.log', cwd=SOURCE)
    (LOGS / 'command-status.json').write_text(json.dumps({'exit_code': result}), encoding='utf-8')
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def import_inputs():
    """Read authenticated artifacts from this public repo, using transfer keys."""
    inputs = json.loads(os.environ.get('PRIVATE_INPUTS') or '[]')
    if not isinstance(inputs, list) or len(inputs) > 8:
        raise ValueError('Encrypted inputs must be a bounded JSON list')
    if not inputs:
        return
    repository = os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Expected the current GitHub repository')
    opener = urllib.request.build_opener(NoRedirect())
    headers = {'Authorization': 'Bearer ' + os.environ['PUBLIC_ARTIFACT_TOKEN'],
               'Accept': 'application/vnd.github+json', 'User-Agent': 'native-project-checks'}
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            raise ValueError('Expected encrypted input metadata')
        identifier, run_id, expected = item.get('artifact_id'), item.get('run_id'), item.get('sha256')
        if (type(identifier) is not int or identifier <= 0 or type(run_id) is not int or run_id <= 0 or
                not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected)):
            raise ValueError('Exact encrypted artifact and run identity are required')
        identity = item.get('transfer_identity', '')
        if not isinstance(identity, str) or len(identity) > 4096:
            raise ValueError('Expected a short-lived age transfer identity')
        lines = [line for line in identity.splitlines() if line and not line.startswith('#')]
        if len(lines) != 1 or not re.fullmatch(r'AGE-SECRET-KEY-1[0-9A-Z]+', lines[0]):
            raise ValueError('Expected a short-lived age transfer identity')
        endpoint = f'https://api.github.com/repos/{repository}/actions/artifacts/{identifier}'
        with opener.open(urllib.request.Request(endpoint, headers=headers), timeout=60) as response:
            metadata = json.load(response)
        if (metadata.get('id') != identifier or metadata.get('expired') is not False or
                metadata.get('workflow_run', {}).get('id') != run_id or
                metadata.get('digest') != 'sha256:' + expected):
            raise ValueError('Encrypted artifact provenance differs')
        try:
            opener.open(urllib.request.Request(endpoint + '/zip', headers=headers), timeout=60)
        except urllib.error.HTTPError as redirect:
            if redirect.code != 302 or not redirect.headers.get('Location'):
                raise
            location = redirect.headers['Location']
        else:
            raise ValueError('Expected a temporary artifact download redirect')
        parsed = urllib.parse.urlsplit(location)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Expected an HTTPS artifact storage location')
        folder = source_path('native-inputs/encrypted/' + str(index))
        folder.mkdir(parents=True, exist_ok=False)
        packed_path, encrypted = folder / 'input.zip', folder / 'native-results.age'
        digest, count = hashlib.sha256(), 0
        # Create a fresh unauthenticated storage request. Never forward the
        # GitHub job token through the cross-host redirect.
        request = urllib.request.Request(location, headers={'User-Agent': 'native-project-checks'})
        with urllib.request.urlopen(request, timeout=60) as response, packed_path.open('xb') as output:
            while block := response.read(1024 * 1024):
                count += len(block)
                if count > 2 * 1024 ** 3:
                    raise ValueError('Encrypted input is too large')
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != expected:
            raise ValueError('Encrypted input checksum differs')
        with zipfile.ZipFile(packed_path) as archive:
            if archive.namelist() != ['native-results.age']:
                raise ValueError('Unexpected encrypted input ZIP members')
            with archive.open('native-results.age') as source, encrypted.open('xb') as output:
                shutil.copyfileobj(source, output)
        key = BUILD_ROOT / ('temporary-transfer-identity-' + str(index))
        try:
            with key.open('x', encoding='ascii') as stream:
                stream.write(identity.rstrip() + '\n')
            key.chmod(0o600)
            status = logged([str(AGE), '-d', '-i', str(key), '-o', str(folder / 'private-results.tar.gz'),
                             str(encrypted)], 'input-decryption.log')
            if status:
                raise RuntimeError('Encrypted input authentication failed')
        finally:
            key.unlink(missing_ok=True)
        packed_path.unlink()
        encrypted.unlink()
        (folder / 'INPUT.json').write_text(json.dumps({'artifact_id': identifier, 'run_id': run_id,
            'zip_sha256': expected, 'owner_private_key_used': False}, indent=2), encoding='utf-8')


def encrypt():
    recipient = os.environ['RESULT_RECIPIENT']
    if not re.fullmatch(r'age1[a-z0-9]+', recipient):
        raise ValueError('An age public recipient is required')
    recipients = [recipient]
    transfer = os.environ.get('TRANSFER_RECIPIENT', '')
    if transfer:
        if not re.fullmatch(r'age1[a-z0-9]+', transfer):
            raise ValueError('The optional transfer recipient must be an age public recipient')
        if transfer not in recipients:
            recipients.append(transfer)
    archive = BUILD_ROOT / 'private-results.tar.gz'
    names = json.loads(os.environ['PRIVATE_RESULT_PATHS'])
    if not isinstance(names, list) or any(not isinstance(x, str) for x in names):
        raise ValueError('Result paths must be a JSON list')
    with tarfile.open(archive, 'w:gz') as packed:
        packed.add(LOGS, arcname='logs')
        for name in names:
            path = source_path(name)
            if path.exists():
                packed.add(path, arcname='results/' + path.relative_to(SOURCE.resolve()).as_posix())
    output = Path.cwd() / 'encrypted-output/native-results.age'
    output.parent.mkdir(exist_ok=True)
    with (LOGS / 'encryption.log').open('ab') as stream:
        recipient_args = [argument for key in recipients for argument in ('-r', key)]
        subprocess.run([str(AGE), *recipient_args, '-o', str(output), str(archive)],
                       check=True, stdout=stream, stderr=stream)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('tools', 'checkout', 'install', 'inputs', 'run', 'encrypt'))
    parser.add_argument('--architecture', choices=('arm64', 'intel'))
    parser.add_argument('--commit')
    args = parser.parse_args()
    LOGS.mkdir(parents=True, exist_ok=True)
    try:
        if args.operation == 'tools':
            tools(args.architecture)
        elif args.operation == 'checkout':
            checkout(args.commit)
        elif args.operation == 'install':
            return install()
        elif args.operation == 'inputs':
            import_inputs()
        elif args.operation == 'run':
            return run_private()
        else:
            encrypt()
        print('Operation completed; private details are kept in encrypted results.')
        return 0
    except Exception as error:
        # Never put private paths, command arguments or exceptions in public logs.
        (LOGS / 'controller-error.txt').write_text(repr(error), encoding='utf-8')
        print('Operation failed; details are kept in the private result bundle.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
