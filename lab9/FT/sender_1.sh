#!/bin/sh
sudo ./sender data.bin node2 21 &
sudo ./sender data.bin node3 31 &
sudo ./sender data.bin node4 41 &
wait
echo "node 1 sent all file segments"