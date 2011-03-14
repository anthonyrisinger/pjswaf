#!/usr/bin/env python


waf_ident = 'waf-1.6.3'
waf_hexdigest = '86000f9349009340ea4124adf4ac1d167c6e012c'

waf_archive = '{0}.tar.bz2'.format(waf_ident)
waf_url = 'http://waf.googlecode.com/files/{0}'.format(waf_archive)

py_version_range = (0x20600ef, 0x30000f0)
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

    class PyFound2x(Exception):
        pass

    def test(py, reexec=True):
        try:
            stdout = subprocess.Popen([py, '-c', _py_version_test], stdout=subprocess.PIPE).communicate()[0]
            if len(stdout) > 0:
                hexversion, executable = [str(x.decode('utf8')) for x in stdout.split(b'\0')]
                if py_version_range[0] < int(hexversion) < py_version_range[1] and os.path.isfile(executable):
                    raise PyFound2x(executable, reexec)
        except OSError:
            pass

    try:
        test(sys.executable, False)
        for py in py_version_scan:
            test(py)
    except PyFound2x as pf:
        return pf.args
    else:
        return None, False


_py_version_test = r"""

import sys
import os

pkg = [
    sys.hexversion,
    os.path.abspath(sys.executable),
]

sys.stdout.write('\0'.join(map(str, pkg)))

"""

if 'PYTHON' in os.environ:
    PYTHON = os.environ['PYTHON']
else:
    PYTHON, reexec = _py_find()
    if PYTHON is not None and reexec is True:
        sys.stderr.write('WARNING: Re-executing under new Python executable ({0}) ...\n'.format(PYTHON))
        os.environ['PYTHON'] = PYTHON
        sys.argv[0:0] = [PYTHON]
        os.execv(PYTHON, sys.argv)
        # possibly needed for windows (no support for process replacement?)
        sys.exit()
    else:
        sys.stderr.write('WARNING: Unable to verify Python executable, ignoring ...\n')
    os.environ['PYTHON'] = PYTHON or sys.executable


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
        # last; it represents the entire match, encompasses all sub-matches if
        # any, and is OR'ed at the top level). The engine is unable to complete
        # the group until it reaches the end of the match.
        return match.expand(map_sub[match.lastgroup])
    def xall(text):
        return re_all.sub(xone, text)
    return xall


def _waf_to_pjs(waf, pjs=None):

    if pjs is None:
        pjs = StringIO.StringIO()
    pjsball = tarfile.open(fileobj=pjs, mode='w')
    re_path = _gen_xform(pjswaf_path_xform)
    re_code = _gen_xform(pjswaf_code_xform)

    # Compound `with` statements are not supported until 2.7 and methinks at
    # least one or two people would throw a fit about this ;-) ... *trying*
    # to keep everything compatible to 2.6 ...
    with tarfile.open(fileobj=waf) as wafball:
        with tarfile.open(fileobj=pjs, mode='w') as pjsball:
            for member in wafball.getmembers():
                member.path = member.path.replace(waf_ident,'').lstrip('./')
                new_path = re_path(member.path)
                if new_path != member.path:
                    member.path = new_path
                    fd_pjs = StringIO.StringIO()
                    fd_pjs.write(re_code(wafball.extractfile(member).read()))
                    member.size = fd_pjs.tell()
                    fd_pjs.seek(0)
                    pjsball.addfile(member, fd_pjs)

    waf.seek(0)
    pjs.seek(0)

    return pjs


def _get_context():

    parser = optparse.OptionParser(description='Download waf, generate pjswaf.')
    cwd = os.getcwd()

    parser.add_option('-b', metavar='BASE', default=cwd, dest='path_base',
        help='BASE working directory [%default]')
    parser.add_option('-u', metavar='URI', dest='waf_uri',
        help='retrieve {0} from URI [BASE/build/{1}, {2}]'.format(waf_ident, waf_archive, waf_url))
    parser.add_option('-d', metavar='SHA1', default=waf_hexdigest, dest='waf_hexdigest',
        help='expected SHA1 digest of URI [%default]')

    ctx, args = parser.parse_args()
    if len(args) > 0:
        raise ValueError('{0} does not accept arguments.'.format(sys.argv[0]))
    if ctx.path_base != cwd:
        ctx.path_base = os.path.abspath(ctx.path_base)

    ctx._update_loose({
        'path_cwd': cwd,
        'path_build': os.path.join(ctx.path_base, 'build'),
        'path_extract': os.path.join(ctx.path_base, 'build', 'pjswaf'),
        'file_waf_archive': os.path.join(ctx.path_base, 'build', waf_archive),
        'file_waf_archive_alt': os.path.join(cwd, waf_archive),
    })

    return ctx


def _get_waf(ctx):

    if not os.access(ctx.path_build, os.R_OK|os.W_OK):
        os.makedirs(ctx.path_build)

    waf = StringIO.StringIO()
    waf_hash = hashlib.sha1()

    if ctx.waf_uri is None:
        uri_scan = [
            ctx.file_waf_archive,
            ctx.file_waf_archive_alt,
            waf_url,
            None,
        ]
    else:
        if ctx.waf_uri[0:7].lower() != 'http://':
            ctx.waf_uri = os.path.abspath(ctx.waf_uri)
        uri_scan = [
            ctx.waf_uri,
            None,
        ]

    for uri_wafz in uri_scan:
        if uri_wafz is None:
            raise RuntimeError('Unable to locate waf archive ({0}).'.format(waf_archive))
        elif uri_wafz[0:7].lower() == 'http://':
            urllib.urlretrieve(uri_wafz, ctx.file_waf_archive)
        elif uri_wafz != ctx.file_waf_archive and os.access(uri_wafz, os.R_OK):
            shutil.copyfile(uri_wafz, ctx.file_waf_archive)
        if os.access(ctx.file_waf_archive, os.R_OK):
            break

    with open(ctx.file_waf_archive, 'rb') as wafz:
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
        pjsball.list()
        pjsball.extractall(ctx.path_extract)
