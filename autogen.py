#!/usr/bin/env python


# Must be a list of path components.
relpath_base = ['altwaf']
relpath_out = ['out']

waf_ident = 'waf-1.6.3'
waf_hexdigest = '86000f9349009340ea4124adf4ac1d167c6e012c'

waf_archive = '{0}.tar.bz2'.format(waf_ident)
waf_url = 'http://waf.googlecode.com/files/{0}'.format(waf_archive)

# Alternative names for waf[lib]/wscript; IDENTIFIERS ONLY.
alt_ident = {'waf': 'pjswaf',
             'wscript': 'jamfile'}

# (regex) `re`  pattern to match against
# (regex) `sub` substitute pattern for `re` (optional)
# (ident) `id`  full `re` match for use in `sub`, eg. \g<my_id> (optional)
#
# The first matching `re` will be used; others will not be tried. `id` must
# be both unique to the group AND valid identifier! Only named groups are
# supported; using numbered groups is undefined (final regex is single-pass).
# If `sub` is ommitted, `re` acts as a filter and `id` is ignored; if `id`
# is ommitted, `sub` will replace full `re` match (if no other groups used).
#
# Waf paths matching any filter are included.
# re, sub, id (see above)
alt_path_filter = [

    # Exec template/generator
    {'re': '^waf-light$'},

    # How to build a build system :-)
    {'re': '^wscript$'},

    # Core library
    {'re': r'^waflib/[^/]*\.py$'},

    # Select few useful core modules
    {'re': r'^waflib/Tools/(__init__|python|errcheck|gnu_dirs)\.py$'},

    # Select few useful 3rd-party modules
    {'re': r'^waflib/extras/(__init__|parallel_debug|why)\.py$'},

]

# Arbitrary code transforms.
# re, sub, id (see above)
alt_code_xform = [

    # Remove the ghost import for now
    {'re': r'\.compat15',
     'sub': ''},

]

# Alternative names for waf[lib]/wscript generated by _get_context().
alt_ident_xlate = []

py_version_range = (0x20600f0, 0x30000f0)
py_version_scan = ('python'+v+s for v in ['2', '2.7', '2.6', ''] for s in ['', '.exe'])


# PREMAIN
import sys, os, subprocess, logging

auto_name = os.path.basename(sys.argv[0]) or 'autogen.py'


class o(object):

    _levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')

    _logger = logging.getLogger()
    _logger.setLevel(logging.NOTSET)
    _logger.name = auto_name

    _handler = logging.StreamHandler()
    _handler.setLevel(logging.DEBUG)

    _formatter = logging.Formatter("%(levelname)8s: %(message)s")
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)

    O = 2
    S = -1
    locals().update([
        (x[0], getattr(logging, x))
        for x in _levels
    ])

    k = _logger.isEnabledFor

    @classmethod
    def out(cls, msg, *args, **kwds):
        o = kwds.pop('o', cls.O)
        msg = msg.format(*args, **kwds)
        if cls.S < o < cls.D:
            o > 0 and sys.stderr.write(o * '    ')
            sys.stderr.write(msg)
            sys.stderr.write('\n')
        else: 
            cls._logger.log(o, msg)
        return msg

_ = o.out


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
            raise RuntimeError(_('Python 2.x required, supplied {0}', py, o=o.C))

        return executable

    py_self = sys.executable and _py_test(sys.executable) or None
    py_export = py_export and _py_test(py_export, True) or py_self

    if not py_export:
        for py in py_version_scan:
            py_export = _py_test(py)
            if py_export:
                break

    if not py_self and not py_export:
        _('Unable to verify PYTHON executable, trying {0} ...', sys.executable, o=o.W)
    elif not py_self and py_export:
        _('Re-executing under {0} ...', py_export, o=o.W)
        os.environ['PYTHON'] = py_export
        sys.argv[0:0] = [py_export]
        os.execv(py_export, sys.argv)
        # possibly needed for windows (no support for process replacement?)
        sys.exit()
    else:
        _('Verified PYTHON as {0} ...', py_export, o=o.I)

    return py_export


# At this point we'll either die, reexec, or try anyways
PYTHON = _py_find() or None
if PYTHON:
    os.environ['PYTHON'] = PYTHON
elif 'PYTHON' in os.environ:
    del os.environ['PYTHON']


# MAIN
import re, urllib, tarfile, StringIO, hashlib, optparse, shutil


def _gen_xform(re_list):
    re_all = []
    map_sub = {}
    for iid, frag in enumerate(re_list):
        iid = frag.get('id') or '__{0}__'.format(iid)
        tracker = '(?P<{0}>{1})'.format(iid, frag['re'])
        re_all.append(tracker)
        if 'sub' in frag:
            map_sub[iid] = frag['sub']
    re_all = re.compile('|'.join(re_all))
    def xone(match):
        # This trick w3rks because the `id` group is gauranteed to match last.
        # OR'ed at top level, group `id` is the entire match, and wraps all
        # sub-groups (if any). As the engine cannot complete the group until
        # it reaches the final char, `lastgroup` will _always_ be `id`.
        re_sub = map_sub.get(match.lastgroup)
        return match.group(0) if re_sub is None else match.expand(re_sub)
    def xall(text):
        return re_all.subn(xone, text)
    return xall


def _waf_to_alt(waf, alt=None):

    _('::::: Generating {0} from waf ...', alt_ident['waf'], o=1)
    if alt is None:
        alt = StringIO.StringIO()
    if PYTHON and sys.platform != 'win32':
        alt_code_xform.append({
            're': '#! */usr/bin/env +python *',
            'sub': '#!{0}'.format(PYTHON),
        })
    altball = tarfile.open(fileobj=alt, mode='w')
    re_path = _gen_xform(alt_path_filter)
    re_code = _gen_xform(alt_code_xform)
    re_ident = _gen_xform(alt_ident_xlate)

    # Compound `with` statements are not supported until 2.7 ...
    with tarfile.open(fileobj=waf) as wafball:
        with tarfile.open(fileobj=alt, mode='w') as altball:
            for member in wafball.getmembers():
                member.path = member.path.replace(waf_ident,'').lstrip('./')
                path_orig = member.path
                member.path, n0 = re_path(member.path)
                if n0 > 0:
                    member.path = re_ident(member.path)[0]
                    alt_fd = StringIO.StringIO()
                    alt_code, n0 = re_code(wafball.extractfile(member).read())
                    alt_code, n1 = re_ident(alt_code)
                    _('+ {0: <3} {1: <36} [{2}]', n0+n1, member.path, path_orig)
                    alt_fd.write(alt_code)
                    member.size = alt_fd.tell()
                    alt_fd.seek(0)
                    altball.addfile(member, alt_fd)

    waf.seek(0)
    alt.seek(0)

    return alt


def _get_context():

    parser = optparse.OptionParser(description='Download waf, generate `--waf`.')
    cwd = os.getcwd()

    parser.add_option('--uri', metavar='URI',dest='waf_uri',
        help='retrieve {0} from URI [<localcache>, <upstream>]'.format(waf_archive))
    parser.add_option('--sha1', metavar='SHA1', default=waf_hexdigest, dest='waf_hexdigest',
        help='expected SHA1 hexdigest of URI [%default]')
    parser.add_option('--waf', metavar='IDENT', default=alt_ident['waf'], dest='alt_waf',
        help='build application name/identity [%default]')
    parser.add_option('--wscript', metavar='FILENAME', default=alt_ident['wscript'], dest='alt_wscript',
        help='instruction filename, eg. Makefile [%default]')

    # Hidden, but available for override; also simplifies updating.
    parser.add_option('--path-cwd', default=cwd, help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-base', help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-out', help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-extract', help=optparse.SUPPRESS_HELP)
    parser.add_option('--path-cache-archive', help=optparse.SUPPRESS_HELP)

    ctx, args = parser.parse_args()
    if len(args) > 0:
        raise ValueError(_('{0} does not accept arguments.', auto_name, o=o.C))

    # Update translations
    if not re.match('^[a-z_][a-z0-9_]*$', ctx.alt_waf, re.I):
        raise ValueError(_('--waf requires an identifier; `{0}` is invalid.', ctx.alt_waf, o=o.C))
    if not re.match('^[a-z_][a-z0-9_]*$', ctx.alt_wscript, re.I):
        raise ValueError(_('--wscript requires an identifier; `{0}` is invalid.', ctx.alt_wscript, o=o.C))
    ctx.alt_waf = alt_ident['waf'] = ctx.alt_waf
    ctx.alt_wscript = alt_ident['wscript'] = ctx.alt_wscript

    # Generate lower, Title, and UPPERCASE versions of `alt_ident`
    alt_ident_xlate[:] = [ 
        {'re': getattr(re_re, op)(), 'sub': getattr(re_sub, op)()}
        for op in ('lower', 'title', 'upper')
            for re_re, re_sub in alt_ident.iteritems()
    ]

    if not ctx.path_cwd:
        ctx.path_cwd = cwd
    if not ctx.path_base:
        ctx.path_base = os.path.join(ctx.path_cwd, *relpath_base)
    if not ctx.path_out:
        ctx.path_out = os.path.join(ctx.path_base, *relpath_out)
    if not ctx.path_extract:
        ctx.path_extract = os.path.join(ctx.path_out, ctx.alt_waf)
    if not ctx.path_cache_archive:
        ctx.path_cache_archive = os.path.join(ctx.path_out, waf_archive)

    for p in ['path_cwd', 'path_base', 'path_out', 'path_extract', 'path_cache_archive']:
        setattr(ctx, p, os.path.abspath(getattr(ctx, p)))

    return ctx


def _get_waf(ctx):

    if not os.access(ctx.path_out, os.R_OK|os.W_OK):
        os.makedirs(ctx.path_out)

    waf = StringIO.StringIO()
    waf_hash = hashlib.sha1()
    waf_pretty = None
    if ctx.waf_uri is None:
        uri_scan = [
            ctx.path_cache_archive,
            os.path.join(ctx.path_base, waf_archive),
            os.path.join(ctx.path_cwd, waf_archive),
            waf_url,
            None,
        ]
    else:
        if ctx.waf_uri[0:7].lower() != 'http://':
            ctx.waf_uri = os.path.abspath(ctx.waf_uri)
            waf_pretty = ctx.waf_uri.replace(os.getcwd(), '.')
        else:
            waf_pretty = ctx.waf_uri
        _('URI to waf archive: {0} ...', waf_pretty , o=o.I)
        uri_scan = [
            ctx.waf_uri,
            None,
        ]

    for uri_wafz in uri_scan:
        if uri_wafz is None:
            raise RuntimeError(_('Unable to locate waf ({0}).', waf_pretty or waf_archive, o=o.C))
        elif uri_wafz[0:7].lower() == 'http://':
            _('Downloading {0} from {1} ...', waf_ident, uri_wafz, o=o.I)
            urllib.urlretrieve(uri_wafz, ctx.path_cache_archive)
        elif uri_wafz != ctx.path_cache_archive and os.access(uri_wafz, os.R_OK):
            _('Copying {0} ...', waf_ident, o=o.I)
            _('  {0} ...', uri_wafz, o=o.I)
            _('+ {0} ...', ctx.path_cache_archive, o=o.I)
            shutil.copyfile(uri_wafz, ctx.path_cache_archive)
        if os.access(ctx.path_cache_archive, os.R_OK):
            break

    with open(ctx.path_cache_archive, 'rb') as wafz:
        kbytes = wafz.read(4096)
        while kbytes:
            waf_hash.update(kbytes)
            waf.write(kbytes)
            kbytes = wafz.read(4096)
        waf.seek(0)

    if waf_hash.hexdigest() != ctx.waf_hexdigest:
        raise ValueError(_('Waf archive is corrupted.', o=o.C))

    return waf


if __name__ == '__main__':

    ctx = _get_context()

    with tarfile.open(fileobj=_waf_to_alt(_get_waf(ctx))) as altball:
        altball.extractall(ctx.path_extract)
