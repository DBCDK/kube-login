#!/usr/bin/env bash
set -e

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/login ./src/*.go
docker build -t docker-platform.dbc.dk/kube-login:dbc-20180626 .
