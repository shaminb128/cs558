#!/bin/sh
sudo ./receiver 21 data_21.bin 10485760 &
sudo ./receiver 23 data_23.bin 10485760 &
sudo ./receiver 24 data_24.bin 10485760 &
wait
echo "node 2 received all file segments"