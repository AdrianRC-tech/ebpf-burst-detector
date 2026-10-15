#!/bin/bash
set -e

docker cp bin/burst-detector burst-detection-lab-worker:/usr/local/bin/burst-detector
docker cp bin/burst-detector burst-detection-lab-worker2:/usr/local/bin/burst-detector
