#!/usr/bin/env python3

from argparse import ArgumentParser
from collections import defaultdict
from hashlib import sha256
from http.client import HTTPResponse
from io import BytesIO
from json import loads
from pathlib import Path
from subprocess import check_output
from sys import exit
from tarfile import open as tar_open
from typing import List, Set
from urllib.request import Request, urlopen

parser = ArgumentParser()
parser.add_argument(
    dest='pkgmirror_url', type=str, help='URL of the pkg mirror')
parser.add_argument(
    dest='jail_root', type=str, help='path of the jail (chroot)')
parser.add_argument(
    dest='packages', type=str, help='space separated list of packages')


def _get_abi(jail_root: str) -> str:
    'Return the used `$ABI` in the future jail.'
    output = check_output(['pkg', '--chroot', jail_root, 'config', 'abi'])
    return output.strip().decode('utf-8')


def _revalidate_packagesite(abi: str, pkgmirror_url: str) -> List[bytes]:
    """
    Revalidate packagesite before fetching and return the new
    `ExFileObject` that is the `packagesite.txz`.
    """
    url_prefix = '/'.join((pkgmirror_url, abi, 'latest'))
    headers = {'Cache-Bypass': 'true'}
    request = Request(url='/'.join((url_prefix, 'meta.txz')), headers=headers)
    response = urlopen(url=request)  # type: HTTPResponse
    request = Request(
        url='/'.join((url_prefix, 'packagesite.txz')), headers=headers)
    response = urlopen(url=request)  # type: HTTPResponse
    archive = tar_open(mode='r:xz', fileobj=BytesIO(response.read()))
    exfile = archive.extractfile('packagesite.yaml')
    return exfile.read().splitlines()


def _load_packages(lines: List[bytes]) -> defaultdict:
    """
    Load and return the packages from the passed JSON structured lines.
    """
    result = defaultdict(dict)
    for line in lines:
        # print(f'{line}\n')
        loaded = loads(line)
        name = loaded['name']
        version = loaded['version']
        result[name][version] = loaded
    return result


def _extract_deps(
        infodict_packages: defaultdict, passed_packages: dict) -> dict:
    'Compile and return the packages to check, including dependencies.'
    result = dict()
    for name, versions in passed_packages.items():
        for version in versions:
            dict_version = infodict_packages[name][version]
            if 'deps' not in dict_version:
                continue
            for depended_pkg, dict_depended_item in \
                    dict_version['deps'].items():
                if depended_pkg not in result:
                    result[depended_pkg] = set()
                result[depended_pkg].add(dict_depended_item['version'])
    if not result:
        return result
    dict_deps = _extract_deps(
        infodict_packages=infodict_packages, passed_packages=result)
    for name, versions in dict_deps.items():
        if name not in result:
            result[name] = set()
        result[name].update(versions)
    return result


def _get_packages_to_check(
    pkgmirror_url: str, abi: str, infodict_packages: defaultdict,
    passed_packages: Set[str],
) -> List[dict]:
    'Compile and return the packages to check.'
    set_not_in_packages = passed_packages - set(infodict_packages)
    if set_not_in_packages:
        raise KeyError(f'Packages not found: {set_not_in_packages}')
    dict_pkgs = {
        name: set(infodict_packages[name]) for name in passed_packages}
    dict_deps = _extract_deps(
        infodict_packages=infodict_packages, passed_packages=dict_pkgs)
    for name, versions in dict_deps.items():
        if name not in dict_pkgs:
            dict_pkgs[name] = set()
        dict_pkgs[name].update(versions)
    url_prefix = '/'.join((pkgmirror_url, abi, 'latest'))
    result = list()
    for name, versions in dict_pkgs.items():
        for version in versions:
            dict_version = infodict_packages[name][version]
            result.append(dict(
                name=name, version=version,
                url='/'.join((url_prefix, dict_version['repopath'])),
                pkgsize=dict_version['pkgsize'], sha256=dict_version['sum']))
    return result


def _fetch_and_get_info(request: Request) -> dict:
    'Fetch the package and return size and SHA256 sum.'
    response = urlopen(url=request)  # type: HTTPResponse
    content = response.read()
    hasher = sha256()
    hasher.update(content)
    return dict(size=len(content), digest=hasher.hexdigest())


def _get_to_revalidate(packages_to_check: List[dict]) -> List[dict]:
    """
    Download the packages in the dict return the mismatched ones in a
    new `dict`.
    """
    to_revalidate = dict()
    for dict_info in packages_to_check:
        name = dict_info['name']
        url = dict_info['url']
        request = Request(url=url)
        dl_info = _fetch_and_get_info(request=request)
        if dict_info['pkgsize'] != dl_info['size']:
            print(f'Size mismatch: {name}')
            to_revalidate.append(dict_info)
            continue
        if dict_info['sha256'] != dl_info['digest']:
            print(f'SHA256 sum mismatch: {name}')
            to_revalidate.append(dict_info)
            continue
        print(f'OK: {name}')
    return to_revalidate


def _revalidate_packages(to_revalidate: List[dict]) -> bool:
    'Revalidate the packages that are mismatched.'
    headers = {'Cache-Bypass': 'true'}
    success = True
    for dict_item in to_revalidate:
        name = dict_item['name']
        url = dict_item['url']
        print(f'Revalidating {name} ... ', end='')
        request = Request(url=url, headers=headers)
        dl_info = _fetch_and_get_info(request=request)
        if dict_item['pkgsize'] != dl_info['size']:
            print('Size mismatch!')
            success = False
            continue
        if dict_item['sha256'] != dl_info['digest']:
            print('SHA256 sum mismatch!')
            success = False
            continue
        print('OK.')
    return success


def _check_pkgmirror_url(url: str):
    'Check the passed URL for format validity.'
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f'Invalid pkgmirror_url {url}')


def run():
    args = parser.parse_args()
    path_jailroot = Path(args.jail_root)
    if not path_jailroot.is_dir():
        raise FileNotFoundError(path_jailroot)
    passed_packages = set(args.packages.split())
    abi = _get_abi(jail_root=args.jail_root)
    _check_pkgmirror_url(url=args.pkgmirror_url)
    lines = _revalidate_packagesite(abi=abi, pkgmirror_url=args.pkgmirror_url)
    infodict_packages = _load_packages(lines=lines)
    packages_to_check = _get_packages_to_check(
        pkgmirror_url=args.pkgmirror_url, abi=abi,
        infodict_packages=infodict_packages,
        passed_packages=passed_packages)
    to_revalidate = _get_to_revalidate(packages_to_check=packages_to_check)
    if to_revalidate:
        if not _revalidate_packages(to_revalidate=to_revalidate):
            exit(1)


if __name__ == '__main__':
    run()
