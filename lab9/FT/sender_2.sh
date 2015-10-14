#!/bin/sh
sudo ./sender data.bin node1 12 &
sudo ./sender data.bin node3 32 &
sudo ./sender data.bin node4 42 &
wait
echo "node 2 sent all file segments"