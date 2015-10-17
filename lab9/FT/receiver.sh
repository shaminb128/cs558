#!/bin/sh
echo "start time span:"
$A = date +%s%N
sudo ./receiver 12 data_12.bin 209715200
date +%s%N