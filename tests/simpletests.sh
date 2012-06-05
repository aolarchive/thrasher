#!/bin/sh
rm -f thrashd.regression.log
../thrashd -c thrashd.regression.conf &
kid1=$!;
sleep 1
../thrashd -c thrashd.regression2.conf &
kid2=$!;
sleep 1
./simpletests.pl
kill $kid2
kill $kid1
