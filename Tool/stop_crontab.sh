#!/bin/bash
for i in $(ps aux|grep /crontab.sh|grep -v grep|tr -s " "|cut -d " " -f 2)
do
    kill -9 $i
done

for i in $(ps aux|grep /merge.sh|grep -v grep|tr -s " "|cut -d " " -f 2)
do
    kill -9 $i
done
