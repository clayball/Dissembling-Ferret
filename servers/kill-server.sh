#!/bin/bash

FPID=`ps ux | grep 'sudo ./dissferretd.py' | awk {'print $2'}`
echo "killing pid ${FPID}"
kill -n 9 $FPID
