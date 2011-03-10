#!/usr/bin/python2
#FIXME allow running by py3k


waf_ident = 'waf-1.6.3'
waf_hash = '86000f9349009340ea4124adf4ac1d167c6e012c'

waf_archive = '{0}.tar.bz2'.format(waf_ident)
waf_url = 'http://waf.googlecode.com/files/{0}'.format(waf_archive)

py_version_range = (0x20600ef, 0x30000f0)
py_version_scan = ('python'+v+s for v in ['2', '2.7', '2.6', ''] for s in ['', '.exe'])


import sys
import os
import subprocess


def _py_find():

    class PyFound2x(Exception):
        pass

    def test(py):
        try:
            stdout = subprocess.Popen([py, '-c', _py_version_test], stdout=subprocess.PIPE).communicate()[0]
            if len(stdout) > 0:
                hexversion, executable = [str(x.decode('utf8')) for x in stdout.split(b'\0')]
                if py_version_range[0] < int(hexversion) < py_version_range[1] and os.path.isfile(executable):
                    raise PyFound2x(executable)
        except OSError:
            pass

    try:
        test(sys.executable)
        for py in py_version_scan:
            test(py)
    except PyFound2x as pf:
        return pf.args[0]
    else:
        return None


_py_version_test = r"""

import sys
import os

info = [
    sys.hexversion,
    os.path.abspath(sys.executable),
]

sys.stdout.write('\0'.join(map(str, info)))

"""

PYTHON = os.environ.get('PYTHON') or _py_find()

if PYTHON is None:
    sys.stderr.write('WARNING: Unable to verify Python executable, ignoring ...\n')


import re
import urllib
import tarfile
import StringIO
from hashlib import sha1
from optparse import OptionParser


INCLUDE = {
    '/': r'(waf-light|wscript)',
    '/waflib/': r'[^/]*\.py',
    '/waflib/Tools/': r'(__init__|python|errcheck|gnu_dirs)\.py',
    '/waflib/extras/': r'(__init__|parallel_debug|why)\.py',
}

RENAME = {
    '^waf-light$': r'pjswaf-light',
    '^waflib': r'pjswaflib',
    'wscript$': r'pjscript',
}

TRANSFORM = {
    'waf': r'pjswaf',
    'Waf': r'Pjswaf',
    'WAF': r'PJSWAF',
    'wscript': r'pjscript',
    'WSCRIPT': r'PJSCRIPT',
    '\.compat15': '',
}


_re_include = [
    re.compile('^{ident}{prefix}{pattern}$'.format(
        ident=re.escape(waf_ident),
        prefix=re.escape(k),
        pattern=v
    ))
    for k, v in INCLUDE.iteritems()
]

_re_rename = [
    (re.compile(k), v)
    for k, v in RENAME.iteritems()
]

_re_transform = [ 
    (re.compile(k), v)
    for k, v in TRANSFORM.iteritems()
]


def include(m):
    for r in _re_include:
        if r.match(m.path):
            m.path = m.path.replace(waf_ident,'').lstrip('./')
            return True
    return False


def rename(m):
    for r in _re_rename:
        m.path = r[0].sub(r[1], m.path)
    return m


def transform(m, fd):
    new = StringIO.StringIO()
    for l in fd:
        for t in _re_transform:
            l = t[0].sub(t[1], l)
        new.write(l)
    m.size = new.tell()
    new.seek(0)
    return m, new


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
    pjsball = tarfile.open(mode='w:gz', fileobj=pjs)
    wafball = tarfile.open(fileobj=waf)
    for m in wafball.getmembers():
        if include(m):
            rename(m)
            pjsball.addfile(*transform(m, wafball.extractfile(m)))
    pjsball.list()
    pjsball.close()
    pjs.seek(0)
    pjsball = tarfile.open(fileobj=pjs)
    pjsball.extractall(buildlib)
    for fd in pjsball, wafball, pjs, waf:
        fd.close()
