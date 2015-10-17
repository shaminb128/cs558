#!/bin/sh
echo "===>start timestamp:"
A=$(date +%s%N)
echo $A
sudo ./sender data1000.bin node4 43
echo "===>end timestamp:"
B=$(date +%s%N)
echo $B
echo "===>Throughput"
echo "1048576000 / ($B - $A) * 1000000000 * 8" | bc -l
echo "bits/second"