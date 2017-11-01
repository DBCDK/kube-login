#!/usr/bin/env bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/login ./src/*.go
docker build -t roffe/kube-login:latest .
docker push roffe/kube-login:latest
