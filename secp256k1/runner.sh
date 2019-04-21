#!/bin/bash
# set devices you want to mine on here, otherwise miner will use all of them
export CUDA_VISIBLE_DEVICES="0,1"
./auto.out > mininglog.log &
