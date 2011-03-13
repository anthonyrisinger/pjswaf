#!/usr/bin/env python


waf_ident = 'waf-1.6.3'
waf_hash = '86000f9349009340ea4124adf4ac1d167c6e012c'

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
    if PYTHON is not None and reexec is False:
        sys.stderr.write('Continuing with current Python executable ...\n')
    elif PYTHON is not None and reexec is True:
        sys.stderr.write('Re-executing under new Python executable ({0}) ...\n'.format(PYTHON))
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
from hashlib import sha1
from optparse import OptionParser


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


def _waf_to_pjs(waf, pjs):

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


if __name__ == '__main__':
    base = os.path.dirname(os.path.abspath(sys.argv[0] or '.'))
    build = os.path.join(base, 'build')
    buildlib = os.path.join(build, 'pjswaf')
    parser = OptionParser()
    parser.add_option('-w', '--uri', metavar='URI', default=os.path.join(build, waf_archive),
        help="retrieve {ident} from URI [{build}, {remote}]".format(ident=waf_ident, build=build, remote=waf_url))
    parser.add_option('-s', '--hash', default=waf_hash,
        help="expected sha1 of URI [%default]")
    opts, args = parser.parse_args()
    if not os.access(build, os.R_OK|os.W_OK):
        os.mkdir(build)
    os.chdir(build)
    try:
        with open(opts.uri, 'rb'):
            wafz = opts.uri
    except IOError:
        wafz = urllib.urlretrieve(waf_url, waf_archive)[0]
    pjs = StringIO.StringIO()
    with open(wafz, 'rb') as w:
        waf = StringIO.StringIO(w.read())
        if sha1(waf.read()).hexdigest() != opts.hash:
            raise ValueError('Waf archive is corrupted.')
        waf.seek(0)
    pjsball = tarfile.open(fileobj=_waf_to_pjs(waf, pjs))
    pjsball.list()
    pjsball.extractall(buildlib)
    for fd in pjsball, pjs, waf:
        fd.close()
