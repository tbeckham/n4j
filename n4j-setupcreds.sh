#!/bin/bash
eval `clcadmin-assume-system-credentials`
DNSDOMAIN=`euctl system.dns.dnsdomain | awk '{print $3}'`
euare-useraddkey admin -wd $DNSDOMAIN > /root/.euca/n4j-admin.ini
echo [global] >> /root/.euca/n4j-admin.ini
echo default-region = $DNSDOMAIN \n >>  /root/.euca/n4j-admin.ini
