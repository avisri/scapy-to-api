#!/bin/bash 

set -o errexit 

server=${1:-sfm-logst-lp001}
port=${2:-9200}
template=${3:-template_ossec}
file=/etc/logstash/template.d/$template.json
[ -s $file ] ||  ( echo "nofile:$file exiting ..." && exit 1)
cat $file | python -m json.tool && echo "xml looks good continuing" || ( echo "file not found or not a proper xml $file .. aborting" && exit 1)
echo "deleteing old...."
curl -XDELETE  $server:$port/_template/$template || echo "no index to delete ... continuing"
echo
echo "uploading new ..."
curl -XPUT     $server:$port/_template/$template/  -d @$file
echo
echo "sucessfull uploaded .. "
