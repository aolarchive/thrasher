#!/usr/bin/python
import os

debug = ARGUMENTS.get('debug', 0)

env = Environment()

env.ParseConfig('pkg-config --cflags --libs glib-2.0')

if int(debug):
    env.Append(CFLAGS='-DDEBUG -ggdb -O2') 
else:
    env.Append(CFLAGS='-O3')

env.Append(LIBS=['event'])
env.Object('libthrasher', ['libthrasher.c'])
env.Program('thrashd', ['iov.c', 'thrashd.c'])
env.Program('master_thrasher', ['libthrasher.c', 'iov.c', 'master_thrasher.c'])
