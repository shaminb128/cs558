#!/bin/sh
sudo ./receiver data.bin data_2.bin 10485760 &
sudo ./sender /tmp/data.bin node1 node2 &
wait
echo "node 3 received all file segments"