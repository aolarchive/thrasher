#!/usr/bin/python
import os, sys
import platform

debug = ARGUMENTS.get('debug', 0)
libthrash_test = ARGUMENTS.get('lthrash-test', 0)

if GetOption('help'):
    sys.exit(1)

env = Environment()

extra_cflags = ARGUMENTS.get('CFLAGS')
extra_libdir = ARGUMENTS.get('LIBDIR')
static       = ARGUMENTS.get('static')

arch = platform.system() 

if arch == 'OpenBSD':
    env.Append(CFLAGS='-DPLATFORM_OPENBSD')
elif arch == 'Linux':
    env.Append(CFLAGS='-DPLATFORM_LINUX')
else:
    print "Unsupported architecture %s" % arch
    sys.exit(1)

if extra_cflags:
    env.Append(CFLAGS=extra_cflags)

if extra_libdir:
    el = extra_libdir.split()
    env.Append(LIBPATH=el)

env.ParseConfig('pkg-config --cflags --libs glib-2.0')

if int(debug):
    env.Append(CFLAGS='-DDEBUG -ggdb -O2') 
else:
    env.Append(CFLAGS='-O3')

env.Append(LIBS=['event'])

if static:
    env.Append(LIBS='rt')
    env.Append(LINKFLAGS='-static')


thrashd_objs = ['iov.c', 'thrashd.c', 'rbl.c', 'httpd.c']
master_thrasher_objs = ['libthrasher.c', 'iov.c', 'master_thrasher.c']

if ARGUMENTS.get('bgp'):
    nenv = env.Clone()
    Export('nenv')
    SConscript(['openbgpd-compat/SConscript'])
    env.Append(CFLAGS='-Iopenbgpd-compat/')
    env.Append(CFLAGS='-DWITH_BGP')
    env.Object('bgp')
    thrashd_objs.append('openbgpd-compat/buffer.o')
    thrashd_objs.append('openbgpd-compat/imsg.o')
    thrashd_objs.append('bgp.c')


env.Object('libthrasher', ['libthrasher.c'])
env.Program('thrashd', thrashd_objs)
env.Program('master_thrasher', master_thrasher_objs)


if libthrash_test:
    env.Append(CFLAGS="-DLIBTHRASHER_MAIN");
    env.Program('libthrasher-test', ['iov.c', 'libthrasher.c'])
