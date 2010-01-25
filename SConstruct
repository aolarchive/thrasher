#!/usr/bin/env python
import os, sys
import platform

objects = ['iov.c', 'rbl.c', 'httpd.c']

global env

def configure():
    conf = Configure(env)
    
    check_headers = ['event.h', 'evhttp.h']
    check_libs    = ['event']

    for header in check_headers:
        if not conf.CheckCHeader(header):
            sys.exit(1)

    for lib in check_libs:
        if not conf.CheckLib(lib):
            sys.exit(1)

    # check for glib2 stuff 
    env.ParseConfig('pkg-config --cflags --libs glib-2.0')

    # set ldflags
    if 'LDFLAGS' in os.environ:
        env.Append(LINKFLAGS = os.environ['LDFLAGS'])
        print 'Checking Custom link flags: %s' % (os.environ['LDFLAGS'])

    if 'CFLAGS' in os.environ:
        env.Append(CFLAGS = os.environ['CFLAGS'])
        print 'Checking Custom cflags: %s' % (os.environ['CFLAGS'])

    # setup the platform
    pl = platform.system()

    print "Checking target platform (%s)" % pl

    if 'OpenBSD' in pl:
        env.Append(CFLAGS='-DPLATFORM_OPENBSD')
    elif 'Linux' in pl:
        env.Append(CFLAGS='-DPLATFORM_LINUX')
    else:
        print "Unknown platform %s" % pl
        sys.exit(1)

    env.Append(CFLAGS = '-Wall')

    enable_bgp    = ARGUMENTS.get('enable-bgp')
    enable_dbg    = ARGUMENTS.get('enable-debug')
    enable_static = ARGUMENTS.get('enable-static')

    if enable_bgp:
        print '>>> Enabling BGP support'
        Export('env')

        SConscript(['openbgpd-compat/SConscript'])

        env.Append(CFLAGS='-Iopenbgpd-compat/')
        env.Append(CFLAGS='-DWITH_BGP')

        objects.append('#openbgpd-compat/buffer.c')
        objects.append('#openbgpd-compat/imsg.c')
        objects.append('bgp.c')

    if enable_dbg:
        print '>>> Enabling debugging support'
        env.Append(CFLAGS="-DDEBUG")

    if enable_static:
        if not conf.CheckLib('rt'):
            sys.exit(1)

        print '>>> Enabling static compile' 
        env.Append(LINKFLAGS='-static')
        

colors = {}
colors['cyan']   = '\033[96m'
colors['purple'] = '\033[95m'
colors['blue']   = '\033[94m'
colors['green']  = '\033[92m'
colors['yellow'] = '\033[93m'
colors['red']    = '\033[91m'
colors['end']    = '\033[0m'

#If the output is not a terminal, remove the colors
if not sys.stdout.isatty():
   for key, value in colors.iteritems():
      colors[key] = ''

compile_source_message        = '%sCompiling %s              ==> %s$SOURCE%s' % \
   (colors['blue'], colors['purple'], colors['yellow'], colors['end'])

compile_shared_source_message = '%sCompiling shared %s       ==> %s$SOURCE%s' % \
   (colors['blue'], colors['purple'], colors['yellow'], colors['end'])

link_program_message          = '%sLinking Program %s        ==> %s$TARGET%s' % \
   (colors['red'], colors['purple'], colors['yellow'], colors['end'])

link_library_message          = '%sLinking Static Library %s ==> %s$TARGET%s' % \
   (colors['red'], colors['purple'], colors['yellow'], colors['end'])

ranlib_library_message        = '%sRanlib Library %s         ==> %s$TARGET%s' % \
   (colors['red'], colors['purple'], colors['yellow'], colors['end'])

link_shared_library_message   = '%sLinking Shared Library %s ==> %s$TARGET%s' % \
   (colors['red'], colors['purple'], colors['yellow'], colors['end'])

env = Environment(ENV=os.environ)
configure()

'''
env['CCCOMSTR']     = compile_source_message
env['SHCCCOMSTR']   = compile_shared_source_message
env['ARCOMSTR']     = link_library_message
env['RANLIBCOMSTR'] = ranlib_library_message
env['SHLINKCOMSTR'] = link_shared_library_message
env['LINKCOMSTR']   = link_program_message
'''

env.Program('thrashd', objects + ['thrashd.c'])
env.Program('master_thrasher', ['libthrasher.c', 'iov.c', 'master_thrasher.c'])
