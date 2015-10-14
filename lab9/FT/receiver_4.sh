#!/bin/sh
sudo ./receiver 41 data_41.bin 10485760 &
sudo ./receiver 42 data_42.bin 10485760 &
sudo ./receiver 43 data_43.bin 10485760 &
wait
echo "node 4 received all file segments"