#!/bin/sh
chmod +x ./ea
./ea /kubernetes/pkg registry.txt
./ea /kubernetes/staging/src/k8s.io vendor.txt
