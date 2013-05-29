#!/bin/sh
cd /home/smartpush/pyapns/pyapns
twistd -r epoll APNS-P4  --port=7077 
