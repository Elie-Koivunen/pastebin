#!/bin/bash

# Interval between samples (seconds)
INTERVAL=5

echo "Starting SyncIQ throughput monitor (Ctrl+C to stop)..."
echo

# Get initial values (bytes out + in across cluster)
read RX0 TX0 <<< $(isi statistics query current \
  --stats node.net.bytes.in,node.net.bytes.out \
  --format=csv | awk -F',' 'NR>1 {rx+=$2; tx+=$3} END {print rx, tx}')

START_TIME=$(date +%s)

while true; do
    sleep $INTERVAL

    # Current values
    read RX1 TX1 <<< $(isi statistics query current \
      --stats node.net.bytes.in,node.net.bytes.out \
      --format=csv | awk -F',' 'NR>1 {rx+=$2; tx+=$3} END {print rx, tx}')

    NOW=$(date +%s)

    # Calculate deltas
    DELTA_BYTES=$(( (RX1 + TX1) - (RX0 + TX0) ))
    ELAPSED=$(( NOW - START_TIME ))

    if [ "$ELAPSED" -gt 0 ]; then
        AVG_BPS=$(( DELTA_BYTES / ELAPSED ))

        # Convert to GB/s (decimal)
        AVG_GBPS=$(awk "BEGIN {printf \"%.2f\", $AVG_BPS/1000000000}")

        echo "Elapsed: ${ELAPSED}s | Average Throughput: ${AVG_GBPS} GB/s"
    fi
done
