#!/bin/sh
echo "===>start timestamp:"
A=$(date +%s%N)
echo $A
sudo ./sender data1000.bin node4 43
B=$(date +%s%N)
echo "===>end timestamp:"
echo $B
echo "===>Throughput"
echo "1048576000 / ($B - $A) * 1000000000 * 8" | bc -l
echo "bits/second"