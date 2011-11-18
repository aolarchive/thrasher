#!/bin/sh
rm -f thrashd.regression.log
../thrashd -c thrashd.regression.conf &
kid=$!;
./simpletests.pl
kill $kid
