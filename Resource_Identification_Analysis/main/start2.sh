#!/bin/sh
chmod +x ./ri
./ri /kubernetes/pkg registry.txt
./ri /kubernetes/staging/src/k8s.io vendor.txt
