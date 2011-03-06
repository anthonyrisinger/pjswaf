#!/usr/bin/python2

import sys
import os
import re
import urllib
import tarfile
import StringIO
from hashlib import sha1
from optparse import OptionParser


IDENT = 'waf-1.6.3'
SHA1 = '86000f9349009340ea4124adf4ac1d167c6e012c'
REMOTE = 'http://waf.googlecode.com/files/{ident}.tar.bz2'.format(ident=IDENT)

INCLUDE = {
    '/': r'(waf-light|wscript)',
    '/waflib/': r'[^/]*\.py',
    '/waflib/Tools/': r'(__init__|python|errcheck|gnu_dirs)\.py',
    '/waflib/extras/': r'(__init__|compat15|parallel_debug|why)\.py',
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
    '^.*compat15#PRELUDE.*$': r'',
}


_re_include = [
    re.compile('^{ident}{prefix}{pattern}$'.format(
        ident=re.escape(IDENT),
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
            m.path = m.path.replace(IDENT,'').lstrip('./')
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
    parser = OptionParser()
    parser.add_option('-w', '--waf', metavar='URI', default=REMOTE,
        help="retrieve {ident} from URI [%default]".format(ident=IDENT))
    parser.add_option('-s', '--sha1', default=SHA1,
        help="expected SHA1 of URI [%default]".format(ident=IDENT))
    opts, args = parser.parse_args()
    base = os.path.dirname(os.path.abspath(sys.argv[0] or '.'))
    build = os.path.join(base, 'build')
    buildlib = os.path.join(build, 'lib')
    if not os.access(build, os.R_OK|os.W_OK):
        os.mkdir(build)
    os.chdir(build)
    wafz = urllib.urlretrieve(opts.waf, IDENT+'.tar.bz2')[0]
    pj = StringIO.StringIO()
    with open(wafz, 'rb') as w:
        if sha1(w.read()).hexdigest() != opts.sha1:
            raise ValueError('Waf archive is corrupted.')
        w.seek(0)
        waf = StringIO.StringIO(w.read())
    pjball = tarfile.open(mode='w:gz', fileobj=pj)
    wafball = tarfile.open(fileobj=waf)
    for m in wafball.getmembers():
        if include(m):
            rename(m)
            pjball.addfile(*transform(m, wafball.extractfile(m)))
    pjball.list()
    pjball.close()
    pj.seek(0)
    pjball = tarfile.open(fileobj=pj)
    pjball.extractall(buildlib)
    for fd in pjball, wafball, pj, waf:
        fd.close()
