#!/bin/sh
sudo ./receiver data.bin data_2.bin 10485760 &
sudo ./sender /tmp/data.bin node3 node1 &
wait
echo "node 2 received all file segments"