#!/bin/sh
sudo ./sender data.bin node1 13 &
sudo ./sender data.bin node2 23 &
sudo ./sender data.bin node4 43 &
wait
echo "node 3 sent all file segments"