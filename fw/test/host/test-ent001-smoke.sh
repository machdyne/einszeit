#!/bin/bash

python3 ez_validate.py collect --port /dev/ttyACM0 --out runs/ent001-smoke \
    --cond-bytes 51840 --raw-bytes 0 --sample-cnt 16384 \
    --allow-storage --sd-detect ignore

python3 ez_validate.py analyze runs/ent001-smoke/conditioned.bin --sequences 3
