#!/bin/bash
CGO_ENABLED=0 go build -ldflags "-s" -trimpath .
