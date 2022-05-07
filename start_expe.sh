#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi


for ((I=1; I<=10; i++))
do
  echo "Start experiment $I"
  sleep 100
  # 1. Run TSHARK
  tshark -i enp1s0f1 -i enp16s0f0 -w "/dev/shm/trace_$I.pcapng" &
  TSHARK_PID=$!

  sleep 10

  # 2. Run BGP daemon
  /home/thomas/libdataplane/local/lib/frr/bgpd &
  BGPD_PID=$!

  # sleep 4500 s (1h15)
  sleep 4500

  # kill all daemons
  kill -INT $BGPD_PID
  kill -INT $TSHARK_PID

  # Move trace to persistent storage
  mv "/dev/shm/trace_$I.pcapng" /home/thomas/libdataplane/saved_traces
  echo "End experiment $I"
done