#!/bin/sh

INTERVAL=5

echo "Starting SyncIQ throughput monitor (Ctrl+C to stop)..."
echo

TOTAL_BPS=0
SAMPLES=0

while true; do
    sleep $INTERVAL

    # Get cluster-wide outbound rate (replication traffic)
    RATE=$(isi statistics query current \
        --stats=cluster.net.ext.bytes.out.rate \
        --format=csv | awk -F',' 'NR>1 {print $2}')

    # Skip empty reads
    if [ -n "$RATE" ]; then
        TOTAL_BPS=$(( TOTAL_BPS + RATE ))
        SAMPLES=$(( SAMPLES + 1 ))

        AVG_BPS=$(( TOTAL_BPS / SAMPLES ))
        AVG_GBPS=$(awk "BEGIN {printf \"%.2f\", $AVG_BPS/1000000000}")

        echo "Samples: $SAMPLES | Avg Throughput: ${AVG_GBPS} GB/s"
    fi
done
