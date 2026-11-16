#!/usr/bin/env python3
"""mingw-headers.py MINGW_HEADERS_SRC OUT: mingw-w64's headers (its
mingw-w64-headers directory: include/, crt/, ddk/) installed for gexcc-win's
Windows x64 programs, which clang compiles for wasm64 with x64's data model.

The headers choose layouts by the target's macros (__x86_64__, _AMD64_,
_M_AMD64 ...), which the wasm64 target does not predefine and programs
must not see (they would take their x86 code paths). Their tests are
answered by a private macro instead, __GEXW_SDK_X64__, which gexcc-win
defines; the headers' own definitions of the target macros are dropped.
The headers whose x64 parts are x86 code (inline asm, x86 intrinsics) keep
their generic paths or are replaced by include-mingw-pre/ (intrin-impl.h's
intrinsics in portable C). A front end that is x86_64 itself (the wasm32-as-i386
plan's end state) needs none of this rewriting, only the overlays."""
import os, re, shutil, sys

SRC, OUT = sys.argv[1], sys.argv[2]

# kept as they are: their x64 paths are x86 code (math.h's x64 paths are C)
KEEP = {'crt/intrin.h', 'crt/excpt.h', 'include/psdk_inc/intrin-impl.h'}

ARCH = r'(?:__x86_64__|__x86_64|_AMD64_|_M_AMD64|_M_X64)'
TEST = re.compile(r'defined\s*\(\s*' + ARCH + r'\s*\)|defined\s+' + ARCH + r'\b')
IFDEF = re.compile(r'^(\s*#\s*if)(n?)def\s+' + ARCH + r'\b')
DEFINE = re.compile(r'^\s*#\s*define\s+' + ARCH + r'\b.*$')

# x86 code inside headers that are otherwise rewritten: (file, old, new)
EDITS = [
    # x86intrin.h and emmintrin.h are clang's x86 intrinsics; the fences and
    # the rest winnt.h names are include-mingw-pre's intrin-impl.h
    ('include/winnt.h', '# include <x86intrin.h>\n', ''),
    ('include/winnt.h', '#include <emmintrin.h>\n', ''),
    # __debugbreak and __fastfail: wasm traps
    ('crt/_mingw.h.in', '  __asm__ __volatile__("int {$}3":);', '  __builtin_trap();'),
    ('crt/_mingw.h.in', '  __asm__ __volatile__("int {$}0x29"::"c"(_Code));', '  (void)_Code; __builtin_trap();'),
]


def winrt_bool(text):
    # WinRT's boolean as C++ bool in template arguments, as the Windows SDK's
    # headers have it: widl writes boolean (unsigned char), and IReference<boolean>
    # is then IReference<BYTE> defined twice
    text = re.sub(r'<boolean ([,>])', r'<bool \1', text)
    return text.replace('<boolean,', '<bool,').replace(',boolean >', ',bool >').replace(',boolean,', ',bool,')


def rewrite(text):
    out = []
    for line in text.split('\n'):
        if re.match(r'\s*#', line):
            if DEFINE.match(line):
                line = '/* (gexcc-win: not defined) ' + line.strip().replace('*/', '* /') + ' */'
            else:
                line = IFDEF.sub(lambda m: '%s%s %sdefined(__GEXW_SDK_X64__)' % (m.group(1), '', '!' if m.group(2) else ''), line)
                line = TEST.sub('defined(__GEXW_SDK_X64__)', line)
        out.append(line)
    return '\n'.join(out)


if os.path.exists(OUT):
    shutil.rmtree(OUT)
os.makedirs(OUT)
for sub, dest in (('include', ''), ('crt', ''), ('ddk/include', '')):
    base = os.path.join(SRC, sub)
    for root, dirs, files in os.walk(base):
        for f in files:
            if not f.endswith(('.h', '.hxx', '.inl', '.h.in')) and '.' in f:
                continue
            rel = os.path.relpath(os.path.join(root, f), base)
            key = os.path.join(sub.split('/')[0], rel)
            o = os.path.join(OUT, dest, rel[:-3] if rel.endswith('.h.in') else rel)
            os.makedirs(os.path.dirname(o), exist_ok=True)
            text = open(os.path.join(root, f), encoding='latin-1').read()
            if rel.endswith('.h.in'):
                text = text.replace('@DEFAULT_MSVCRT_VERSION@', '0xE00').replace('@DEFAULT_WIN32_WINNT@', '0xa00')
            if key not in KEEP:
                text = rewrite(text)
            if re.match(r'include/windows\.[\w.]+\.h$', key):
                text = winrt_bool(text)
            for f2, old, new in EDITS:
                if f2 == key:
                    assert old in text, (key, old)
                    text = text.replace(old, new)
            open(o, 'w', encoding='latin-1').write(text)
