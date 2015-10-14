#!/bin/sh
sudo ./receiver 12 data_12.bin 10485760 &
sudo ./receiver 13 data_13.bin 10485760 &
sudo ./receiver 14 data_14.bin 10485760 &
wait
echo "node 1 received all file segments"