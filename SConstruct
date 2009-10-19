#!/usr/bin/python
import os, sys

debug = ARGUMENTS.get('debug', 0)

if GetOption('help'):
    sys.exit(1)

env = Environment()

extra_cflags = ARGUMENTS.get('CFLAGS')

if extra_cflags:
    env.Append(CFLAGS=extra_cflags)

env.ParseConfig('pkg-config --cflags --libs glib-2.0')

if int(debug):
    env.Append(CFLAGS='-DDEBUG -ggdb -O2') 
else:
    env.Append(CFLAGS='-O3')

env.Append(LIBS=['event'])
env.Object('libthrasher', ['libthrasher.c'])
env.Program('thrashd', ['iov.c', 'thrashd.c'])
env.Program('master_thrasher', ['libthrasher.c', 'iov.c', 'master_thrasher.c'])
