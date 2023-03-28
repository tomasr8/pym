#!/bin/bash

echo "auth 1"
python service_1.py ken &
echo "auth 2"
python service_1.py denis
