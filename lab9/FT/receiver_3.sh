#!/bin/sh
sudo ./receiver 31 data_31.bin 10485760 &
sudo ./receiver 32 data_32.bin 10485760 &
sudo ./receiver 34 data_34.bin 10485760 &
wait
echo "node 3 received all file segments"