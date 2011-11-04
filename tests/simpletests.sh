#!/bin/sh
./thrashd -c thrashd.regression.conf &
kid=$!;
./simpletests.pl
kill $kid
