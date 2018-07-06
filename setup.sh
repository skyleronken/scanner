#!/bin/bash

echo "Generating API Keys"
openssl req -new -x509 -days 365 -nodes -out api_cert.pem -keyout api_key.pem
echo "Generating Agent Keys"
openssl req -new -x509 -days 365 -nodes -out agent_cert.pem -keyout agent_key.pem
echo "Starting Mongod"
sudo mongod --smallfiles &