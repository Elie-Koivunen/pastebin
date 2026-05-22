#!/bin/sh

INTERVAL=5

echo "Starting SyncIQ throughput monitor (Ctrl+C to stop)..."
echo

# Initial sample
set -- $(isi statistics query current \
  --stats node.net.bytes.in,node.net.bytes.out \
  --format=csv | awk -F',' 'NR>1 {rx+=$2; tx+=$3} END {print rx, tx}')

RX0=$1
TX0=$2

START_TIME=$(date +%s)

while true; do
    sleep $INTERVAL

    set -- $(isi statistics query current \
      --stats node.net.bytes.in,node.net.bytes.out \
      --format=csv | awk -F',' 'NR>1 {rx+=$2; tx+=$3} END {print rx, tx}')

    RX1=$1
    TX1=$2

    NOW=$(date +%s)

    TOTAL_BYTES=$(( (RX1 + TX1) - (RX0 + TX0) ))
    ELAPSED=$(( NOW - START_TIME ))

    if [ "$ELAPSED" -gt 0 ]; then
        AVG_BPS=$(( TOTAL_BYTES / ELAPSED ))

        AVG_GBPS=$(awk "BEGIN {printf \"%.2f\", $AVG_BPS/1000000000}")

        echo "Elapsed: ${ELAPSED}s | Avg Throughput: ${AVG_GBPS} GB/s"
    fi
done
