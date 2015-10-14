#!/bin/sh
sudo ./sender data.bin node1 14 &
sudo ./sender data.bin node2 24 &
sudo ./sender data.bin node3 34 &
wait
echo "node 4 sent all file segments"