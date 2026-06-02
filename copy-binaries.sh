#!/bin/bash
set -e

docker cp bin/ingress-counter burst-detection-lab-worker:/usr/local/bin/ingress-counter
docker cp bin/ingress-counter burst-detection-lab-worker2:/usr/local/bin/ingress-counter
docker cp bin/cusum-detector burst-detection-lab-worker:/usr/local/bin/cusum-detector
docker cp bin/cusum-detector burst-detection-lab-worker2:/usr/local/bin/cusum-detector