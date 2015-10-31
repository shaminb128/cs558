#!/bin/sh
sudo ./receiver data.bin data_2.bin 10485760 &
sudo ./sender /tmp/data.bin node2 node3 &
wait
echo "node 1 received all file segments"