#!/usr/bin/python2


import re
import urllib
import tarfile
import StringIO
from hashlib import sha1


IDENT = 'waf-1.6.3'
SHA1 = '86000f9349009340ea4124adf4ac1d167c6e012c'
LOCATION = 'http://waf.googlecode.com/files/{ident}.tar.bz2'.format(ident=IDENT)

INCLUDE = {
    '/':                r'waf-light',
    '/waflib/':         r'[^/]*\.py',
    '/waflib/Tools/':   r'(__init__|python|errcheck|gnu_dirs)\.py',
    '/waflib/extras/':  r'(__init__|compat15|parallel_debug|why)\.py',
}

RENAME = {
    '^waf-light$':      r'pj-light',
    '^waflib':          r'pjlib',
    'wscript$':         r'pjscript',
}

TRANSFORM = {
    'waf':              r'pj',
    'Waf':              r'Pj',
    'WAF':              r'PJ',
    'wscript':          r'pjscript',
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
    waf = urllib.urlopen(LOCATION).read()
    if sha1(waf).hexdigest() != SHA1:
        raise ValueError('Waf archive is corrupt.')
    pj = StringIO.StringIO()
    waf = StringIO.StringIO(waf)
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
    pjball.extractall()
    for fd in pjball, wafball, pj, waf:
        fd.close()
