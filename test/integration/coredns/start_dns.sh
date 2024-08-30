#!/bin/bash

docker run -dit --name coredns --restart=always --volume=./:/data/ -p 53:53/udp coredns/coredns -conf /data/Corefile
