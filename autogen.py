#!/usr/bin/env python

# Must be an iterable.
relpath_build = ('waf2pjs', 'build')

waf_ident = 'waf-1.6.3'
waf_hexdigest = '86000f9349009340ea4124adf4ac1d167c6e012c'

waf_archive = '{0}.tar.bz2'.format(waf_ident)
waf_url = 'http://waf.googlecode.com/files/{0}'.format(waf_archive)

py_version_range = (0x20600f0, 0x30000f0)
py_version_scan = ('python'+v+s for v in ['2', '2.7', '2.6', ''] for s in ['', '.exe'])

# (ident, match, sub)
# The first matching expression will be used; others are not tried. `ident` must
# be both unique AND valid identifier! Only named groups are supported; numbered
# groups will produce unexpected results (final regex is combined, single-pass).
pjswaf_path_xform = [

    ('light',
    r'^waf-light$',
        r'pjswaf-light'),

    ('jam',
    r'^wscript$',
        r'jamfile'),

    ('lib',
    r'^waflib/[^/]*\.py$',
        r'pjs\g<lib>'),

    ('tools',
    r'^waflib/Tools/(__init__|python|errcheck|gnu_dirs)\.py$',
        r'pjs\g<tools>'),

    ('extras',
    r'^waflib/extras/(__init__|parallel_debug|why)\.py$',
        r'pjs\g<extras>'),

]

# (ident, match, sub)
# Same as above.
pjswaf_code_xform = [

    ('waf0',
    r'waf',
        r'pjswaf'),

    ('waf1',
    r'Waf',
        r'Pjswaf'),

    ('waf2',
    r'WAF',
        r'PJSWAF'),

    ('jam0',
    r'wscript',
        r'jamfile'),

    ('jam1',
    r'WSCRIPT',
        r'JAMFILE'),

    ('compat',
    r'\.compat15',
        r''),

]


import sys
import os
import subprocess


def _py_find():

    py_export = os.environ.get('PYTHON')
    py_test = '\n'.join([
        'import sys, os',
        't = [sys.hexversion, os.path.abspath(sys.executable)]',
        'sys.stdout.write("\\0".join(map(str, t)))',
    ])

    def _py_test(py, required=False):

        executable = None

        try:
            stdout = subprocess.Popen([py, '-c', py_test], stdout=subprocess.PIPE).communicate()[0]
        except OSError:
            pass
        else:
            if len(stdout) > 0:
                h, e = [str(x.decode('utf8')) for x in stdout.split(b'\0')]
                if py_version_range[0] <= int(h) < py_version_range[1] and os.path.isfile(e):
                    executable = e

        if required and executable is None:
            raise RuntimeError('FATAL: Python 2.x required, supplied {0}'.format(py))

        return executable

    py_self = sys.executable and _py_test(sys.executable) or None
    py_export = py_export and _py_test(py_export, True) or py_self

    if not py_export:
        for py in py_version_scan:
            py_export = _py_test(py)
            if py_export:
                break

    if not py_self and not py_export:
        sys.stderr.write('WARN: Unable to verify PYTHON executable, trying {0} ...\n'.format(sys.executable))
    elif not py_self and py_export:
        sys.stderr.write('WARN: Re-executing under {0} ...\n'.format(py_export))
        os.environ['PYTHON'] = py_export
        sys.argv[0:0] = [py_export]
        os.execv(py_export, sys.argv)
        # possibly needed for windows (no support for process replacement?)
        sys.exit()
    else:
        sys.stderr.write('INFO: Verified PYTHON as {0} ...\n'.format(py_export))

    return py_export


# At this point we'll either die, reexec, or try anyways
PYTHON = _py_find() or None
if PYTHON:
    os.environ['PYTHON'] = PYTHON
elif 'PYTHON' in os.environ:
    del os.environ['PYTHON']


import re
import urllib
import tarfile
import StringIO
import hashlib
import optparse
import shutil


def _gen_xform(re_list):
    re_all = []
    map_sub = {}
    for ident, pattern, sub in re_list:
        re_all.append('(?P<{0}>{1})'.format(ident, pattern))
        map_sub[ident] = sub
    re_all = re.compile('|'.join(re_all))
    def xone(match):
        # This little trick works because the `ident` group always matches
        # last -- it represents the entire match, encompasses all sub-matches
        # (if any), and OR'ed at the top level. The engine cannot complete
        # the group until it reaches the end of the match ... thus `lastgroup`
        # _always_ points to `ident` ...
        return match.expand(map_sub[match.lastgroup])
    def xall(text):
        return re_all.subn(xone, text)
    return xall


def _waf_to_pjs(waf, pjs=None):

    sys.stderr.write('INFO: Generating pjswaf from waf ...\n')
    if pjs is None:
        pjs = StringIO.StringIO()
    if PYTHON and sys.platform != 'win32':
        pjswaf_code_xform.append((
            '__bang__',
                '#! */usr/bin/env +python *',
                '#!{0}'.format(PYTHON),
        ))
    pjsball = tarfile.open(fileobj=pjs, mode='w')
    re_path = _gen_xform(pjswaf_path_xform)
    re_code = _gen_xform(pjswaf_code_xform)

    # Compound `with` statements are not supported until 2.7 ...
    with tarfile.open(fileobj=waf) as wafball:
        with tarfile.open(fileobj=pjs, mode='w') as pjsball:
            for member in wafball.getmembers():
                member.path = member.path.replace(waf_ident,'').lstrip('./')
                path_orig = member.path
                member.path, n = re_path(member.path)
                if n > 0:
                    sys.stderr.write('    + ')
                    fd_pjs = StringIO.StringIO()
                    code_pjs, n = re_code(wafball.extractfile(member).read())
                    sys.stderr.write('{0: <3} {1: <36} [{2}]\n'.format(n, member.path, path_orig))
                    fd_pjs.write(code_pjs)
                    member.size = fd_pjs.tell()
                    fd_pjs.seek(0)
                    pjsball.addfile(member, fd_pjs)

    waf.seek(0)
    pjs.seek(0)

    return pjs


def _get_context():

    parser = optparse.OptionParser(description='Download waf, generate pjswaf.')
    cwd = os.getcwd()

    parser.add_option('-u', metavar='URI', dest='waf_uri',
        help='retrieve {0} from URI [BASE/build/{1}, {2}]'.format(waf_ident, waf_archive, waf_url))
    parser.add_option('-d', metavar='SHA1', default=waf_hexdigest, dest='waf_hexdigest',
        help='expected SHA1 digest of URI [%default]')

    # Hidden, but available for override; also simplifies updating.
    parser.add_option('--path-cwd', default=cwd, help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-base', default=cwd, help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-build', default=None, help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-extract', default=None, help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-waf-archive', default=None, help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-waf-archive-alt', default=None, help=optparse.SUPPRESS_HELP)

    ctx, args = parser.parse_args()
    if len(args) > 0:
        raise ValueError('{0} does not accept arguments.'.format(sys.argv[0]))

    if not ctx.path_cwd:
        ctx.path_cwd = cwd
    if not ctx.path_base:
        ctx.path_base = cwd
    if not ctx.path_build:
        ctx.path_build = os.path.join(ctx.path_base, *relpath_build)
    if not ctx.path_extract:
        ctx.path_extract = os.path.join(ctx.path_build, 'pjswaf')
    if not ctx.path_waf_archive:
        ctx.path_waf_archive = os.path.join(ctx.path_build, waf_archive)
    if not ctx.path_waf_archive_alt:
        ctx.path_waf_archive_alt = os.path.join(cwd, waf_archive)

    for p in ['cwd','base','build','extract','waf_archive','waf_archive_alt']:
        p = 'path_' + p
        setattr(ctx, p, os.path.abspath(getattr(ctx, p)))

    return ctx


def _get_waf(ctx):

    if not os.access(ctx.path_build, os.R_OK|os.W_OK):
        os.makedirs(ctx.path_build)

    waf = StringIO.StringIO()
    waf_hash = hashlib.sha1()
    if ctx.waf_uri is None:
        uri_scan = [
            ctx.path_waf_archive,
            ctx.path_waf_archive_alt,
            waf_url,
            None,
        ]
    else:
        if ctx.waf_uri[0:7].lower() != 'http://':
            ctx.waf_uri = os.path.abspath(ctx.waf_uri)
            if not os.access(ctx.waf_uri, os.R_OK):
                raise RuntimeError('Waf archive {0} does not exist.'.format(ctx.waf_uri))
        sys.stderr.write('INFO: URI to waf archive: {0} ...\n'.format(ctx.waf_uri))
        uri_scan = [
            ctx.waf_uri,
            None,
        ]

    for uri_wafz in uri_scan:
        if uri_wafz is None:
            raise RuntimeError('Unable to locate waf archive ({0}).'.format(waf_archive))
        elif uri_wafz[0:7].lower() == 'http://':
            sys.stderr.write('INFO: Downloading {0} from {1} ...\n'.format(waf_ident, uri_wafz))
            urllib.urlretrieve(uri_wafz, ctx.path_waf_archive)
        elif uri_wafz != ctx.path_waf_archive and os.access(uri_wafz, os.R_OK):
            sys.stderr.write('INFO: Copying {0} ...\n'.format(waf_ident))
            sys.stderr.write('      {0}\n    + {1}\n'.format(uri_wafz, ctx.path_waf_archive))
            shutil.copyfile(uri_wafz, ctx.path_waf_archive)
        if os.access(ctx.path_waf_archive, os.R_OK):
            break

    with open(ctx.path_waf_archive, 'rb') as wafz:
        kbytes = wafz.read(4096)
        while kbytes:
            waf_hash.update(kbytes)
            waf.write(kbytes)
            kbytes = wafz.read(4096)
        waf.seek(0)

    if waf_hash.hexdigest() != ctx.waf_hexdigest:
        raise ValueError('Waf archive is corrupted.')

    return waf


if __name__ == '__main__':

    ctx = _get_context()

    with tarfile.open(fileobj=_waf_to_pjs(_get_waf(ctx))) as pjsball:
        pjsball.extractall(ctx.path_extract)
