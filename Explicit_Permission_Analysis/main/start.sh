#!/bin/sh
go run main.go /kubernetes/pkg registry.txt
go run main.go /kubernetes/staging/src/k8s.io vendor.txt
