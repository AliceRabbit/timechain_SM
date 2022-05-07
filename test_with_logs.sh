#!/bin/bash

docker rmi time_chain && docker build -t time_chain . && sleep 60 && docker-compose stop && ./export_logs.sh && docker-compose down