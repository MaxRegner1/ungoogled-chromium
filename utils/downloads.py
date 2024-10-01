#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Module for downloading, verifying, and unpacking necessary files into the source tree, with added support for ChromeOS-specific handling.
"""

import argparse
import configparser
import enum
import hashlib
import shutil
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

from _common import ENCODING, USE_REGISTRY, ExtractorEnum, get_logger, \
    get_chromium_version, add_common_params
from _extraction import extract_tar_file, extract_with_7z, extract_with_winrar

sys.path.insert(0, str(Path(__file__).parent / 'third_party'))
import schema #pylint: disable=wrong-import-position, wrong-import-order
sys.path.pop(0)

# Constants for ChromeOS integration


class HashesURLEnum(str, enum.Enum):
    """Enum for supported hash URL schemes, now supporting ChromeOS"""
    CHROMIUM = 'chromium'
    CHROMEOS = 'chromeos'  # Added ChromeOS hash option


class HashMismatchError(BaseException):
    """Exception for computed hashes not matching expected hashes"""


class DownloadInfo:  # pylint: disable=too-few-public-methods
    """Representation of an downloads.ini file for downloading files with ChromeOS handling"""

    _hashes = ('md5', 'sha1', 'sha256', 'sha512')
    hash_url_delimiter = '|'
    _nonempty_keys = ('url', 'download_filename')
    _optional_keys = (
        'version',
        'strip_leading_dirs',
    )
    _passthrough_properties = (*_nonempty_keys, *_optional_keys, 'extractor', 'output_path')
    _ini_vars = {
        '_chromium_version': get_chromium_version(),
    }

    @staticmethod
    def _is_hash_url(value):
        return value.count(DownloadInfo.hash_url_delimiter) == 2 and value.split(
            DownloadInfo.hash_url_delimiter)[0] in iter(HashesURLEnum)

    _schema = schema.Schema({
        schema.Optional(schema.And(str, len)): {
            **{x: schema.And(str, len)
               for x in _nonempty_keys},
            'output_path': (lambda x: str(Path(x).relative_to(''))),
            **{schema.Optional(x): schema.And(str, len)
               for x in _optional_keys},
            schema.Optional('extractor'): schema.Or(ExtractorEnum.TAR, ExtractorEnum.SEVENZIP,
                                                    ExtractorEnum.WINRAR),
            schema.Optional(schema.Or(*_hashes)): schema.And(str, len),
            schema.Optional('hash_url'): lambda x: DownloadInfo._is_hash_url(x),  # pylint: disable=unnecessary-lambda
        }
    })

    class _DownloadsProperties:  # pylint: disable=too-few-public-methods
        def __init__(self, section_dict, passthrough_properties, hashes):
            self._section_dict = section_dict
            self._passthrough_properties = passthrough_properties
            self._hashes = hashes

        def has_hash_url(self):
            """Checks if the current download has a hash URL, now including ChromeOS"""
            return 'hash_url' in self._section_dict

        def __getattr__(self, name):
            if name in self._passthrough_properties:
                return self._section_dict.get(name, fallback=None)
            if name == 'hashes':
                hashes_dict = {}
                for hash_name in (*self._hashes, 'hash_url'):
                    value = self._section_dict.get(hash_name, fallback=None)
                    if value:
                        if hash_name == 'hash_url':
                            value = value.split(DownloadInfo.hash_url_delimiter)
                        hashes_dict[hash_name] = value
                return hashes_dict
            raise AttributeError('"{}" has no attribute "{}"'.format(type(self).__name__, name))

    def _parse_data(self, path):
        """Parses an INI file, compatible with ChromeOS-based download specifications"""
        def _section_generator(data):
            for section in data:
                if section == configparser.DEFAULTSECT:
                    continue
                yield section, dict(
                    filter(lambda x: x[0] not in self._ini_vars, data.items(section)))

        new_data = configparser.ConfigParser(defaults=self._ini_vars)
        with path.open(encoding=ENCODING) as ini_file:
            new_data.read_file(ini_file, source=str(path))
        try:
            self._schema.validate(dict(_section_generator(new_data)))
        except schema.SchemaError as exc:
            get_logger().error('downloads.ini failed schema validation (located in %s)', path)
            raise exc
        return new_data

    def __init__(self, ini_paths):
        """Reads INI files for downloads with ChromeOS options"""
        self._data = configparser.ConfigParser()
        for path in ini_paths:
            self._data.read_dict(self._parse_data(path))

    def __getitem__(self, section):
        """Returns an object with keys as attributes and values pre-processed"""
        return self._DownloadsProperties(self._data[section], self._passthrough_properties,
                                         self._hashes)

    def __contains__(self, item):
        """Checks if a section exists"""
        return self._data.has_section(item)

    def __iter__(self):
        """Iterates over section names"""
        return iter(self._data.sections())

    def properties_iter(self):
        """Iterator for download properties sorted by output path"""
        return sorted(map(lambda x: (x, self[x]), self),
                      key=(lambda x: str(Path(x[1].output_path))))


class _UrlRetrieveReportHook:  # pylint: disable=too-few-public-methods
    """Hook for urllib.request.urlretrieve to log progress information to the console"""
    def __init__(self):
        self._max_len_printed = 0
        self._last_percentage = None

    def __call__(self, block_count, block_size, total_size):
        total_blocks = -(-total_size // block_size)
        if total_blocks > 0:
            percentage = round(block_count / total_blocks, ndigits=3)
            if percentage == self._last_percentage:
                return
            self._last_percentage = percentage
            print('\r' + ' ' * self._max_len_printed, end='')
            status_line = 'Progress: {:.1%} of {:,d} B'.format(percentage, total_size)
        else:
            downloaded_estimate = block_count * block_size
            status_line = 'Progress: {:,d} B of unknown size'.format(downloaded_estimate)
        self._max_len_printed = len(status_line)
        print('\r' + status_line, end='')


def _download_via_urllib(url, file_path, show_progress, disable_ssl_verification):
    reporthook = None
    if show_progress:
        reporthook = _UrlRetrieveReportHook()
    if disable_ssl_verification:
        orig_https_context = ssl._create_default_https_context  # pylint: disable=protected-access
        ssl._create_default_https_context = ssl._create_unverified_context  # pylint: disable=protected-access
    try:
        urllib.request.urlretrieve(url, str(file_path), reporthook=reporthook)
    finally:
        if disable_ssl_verification:
            ssl._create_default_https_context = orig_https_context  # pylint: disable=protected-access
    if show_progress:
        print()


def _download_if_needed(file_path, url, show_progress, disable_ssl_verification):
    """
    Downloads a file from url to the specified path if necessary.
    """
    if file_path.exists():
        get_logger().info('%s already exists. Skipping download.', file_path)
        return

    tmp_file_path = file_path.with_name(file_path.name + '.partial')

    if tmp_file_path.exists():
        get_logger().debug('Resuming downloading URL %s ...', url)
    else:
        get_logger().debug('Downloading URL %s ...', url)

    if shutil.which('curl'):
        get_logger().debug('Using curl')
        try:
            subprocess.run(['curl', '-fL', '-o', str(tmp_file_path), '-C', '-', url], check=True)
        except subprocess.CalledProcessError as exc:
            get_logger().error('curl failed. Re-run the download command to resume downloading.')
            raise exc
    else:
        get_logger().debug('Using urllib')
        _download_via_urllib(url, tmp_file_path, show_progress, disable_ssl_verification)

    tmp_file_path.rename(file_path)


def _chromium_hashes_generator(hashes_path):
    with hashes_path.open(encoding=ENCODING) as hashes_file:
        hash_lines = hashes_file.read().splitlines()
    for hash_name, hash_hex, _ in map(lambda x: x.lower().split('  '), hash_lines):
        if hash_name in hashlib.algorithms_available:
            yield hash_name, hash_hex
        else:
            get_logger().warning('Skipping unknown hash algorithm: %s', hash_name)


def _get_hash_pairs(download_properties, cache_dir):
    """Generator of (hash_name, hash_hex) for the given download"""
    for entry_type, entry_value in download_properties.hashes.items():
        if entry_type == 'hash_url':
            hash_processor, hash_filename, _ = entry_value
            if cache_dir:
                hash_cache_path = cache_dir / 'chromium_hashes' / hash_filename
                if hash_cache_path.exists():
                    yield from _chromium_hashes_generator(hash_cache_path)
                else:
                    download_url = '{}{}'.format(hash_processor, hash_filename)
                    get_logger().info('Downloading Chromium hashes file from %s ...', download_url)
                    _download_if_needed(hash_cache_path, download_url, show_progress=True,
                                        disable_ssl_verification=False)
                    yield from _chromium_hashes_generator(hash_cache_path)
            else:
                raise RuntimeError(
                    'Hashes should be cached in the .local\chromium_hashes directory to work')
        else:
            yield entry_type, entry_value


def _get_extractor_function(extractor):
    if extractor == ExtractorEnum.SEVENZIP:
        return extract_with_7z
    if extractor == ExtractorEnum.WINRAR:
        return extract_with_winrar
    return extract_tar_file


def _verify_hashes(download_properties, download_file_path, cache_dir):
    """Verifies the given file against hashes defined in the ini file"""
    if not download_properties.hashes:
        return
    get_logger().info('Verifying file hashes...')
    hash_obj_pairs = [(hash_name, hashlib.new(hash_name))
                      for hash_name, _ in _get_hash_pairs(download_properties, cache_dir)]
    with download_file_path.open('rb') as download_file:
        while True:
            file_data = download_file.read(2**20)
            if not file_data:
                break
            for _, hash_obj in hash_obj_pairs:
                hash_obj.update(file_data)
    hash_errors = []
    for hash_name, hash_obj in hash_obj_pairs:
        hash_hex = next(hex_ for name_, hex_ in _get_hash_pairs(download_properties, cache_dir)
                        if name_ == hash_name)
        if hash_obj.hexdigest() != hash_hex:
            hash_errors.append('{} mismatch: expected {} but got {}'.format(
                hash_name, hash_hex, hash_obj.hexdigest()))
    if hash_errors:
        raise HashMismatchError('\n'.join(hash_errors))


def _extract_file(download_properties, download_file_path, source_tree):
    extractor = _get_extractor_function(download_properties.extractor)
    extract_root = source_tree / download_properties.output_path
    get_logger().info('Extracting downloaded archive %s to %s ...', download_file_path, extract_root)
    extractor(download_file_path, extract_root, strip_leading_dirs=int(
        download_properties.strip_leading_dirs or 0))


def download_ini_file(ini_paths, *, source_tree, show_progress, disable_ssl_verification,
                      ignore_hash_mismatch, download_cache=None):
    """
    Downloads all sections of a downloads.ini file and extracts them into the source tree.
    """
    ini_file = DownloadInfo(ini_paths)
    for section_name, download_properties in ini_file.properties_iter():
        file_path = source_tree / download_properties.output_path / download_properties.download_filename
        try:
            _download_if_needed(file_path, download_properties.url, show_progress,
                                disable_ssl_verification)
            _verify_hashes(download_properties, file_path, download_cache)
        except HashMismatchError as exc:
            if not ignore_hash_mismatch:
                raise exc
        _extract_file(download_properties, file_path, source_tree)


def main(argv=None):
    """CLI entry point"""

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=sys.modules[__name__].__doc__,
        formatter_class=argparse.RawTextHelpFormatter)
    add_common_params(parser)
    parser.add_argument('--downloads-ini', required=True, action='append',
                        type=Path,
                        help='Required: download the files specified in the downloads.ini file(s)')
    args = parser.parse_args(argv)

    logger = get_logger(args)

    try:
        download_ini_file(args.downloads_ini,
                          source_tree=args.source_tree,
                          show_progress=args.show_progress,
                          disable_ssl_verification=args.disable_ssl_verification,
                          ignore_hash_mismatch=args.ignore_hash_mismatch,
                          download_cache=args.download_cache)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error('Download failed: %s', exc)
        sys.exit(1)


if __name__ == '__main__':
    main()
