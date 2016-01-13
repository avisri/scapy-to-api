#!/usr/bin/env python 

import json
import sys 
import re
import requests
from pyparsing import Word, alphas, Suppress, Combine, nums, string, Optional, Regex
from time import strftime
import traceback

def post(evtype,data):
    if evtype == "windows":
        url="http://localhost:4002/api/windows"
    elif evtype == "nix":
        url="http://localhost:4001/api/nix"

    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(url, data=json.dumps(data), headers=headers)
    except Exception as ex:
	exc_info = sys.exc_info()
        print "Can't post :[%s]" %json.dumps(data)
	traceback.print_exception(*exc_info)
	del exc_info
	pass
   
def parse_header(header):
    parts=header.split()
    server_time="{0} {1} {2} {3}".format(parts[0],parts[1],parts[2],parts[3])
    agent_name="{0}".format(parts[4][1:-1])
    remparts=parts[5].split('->')
    ip_range_any=remparts[0]
    path=remparts[1]
    return { 'server_time': server_time, 'agent_name': agent_name, 'ip_range_any': ip_range_any, 'path': path }

def merge( a, b):
    c=a
    c.update(b) 
    return c

def flattenDict(d, result=None):
    if result is None:
        result = {}
    for key in d:
        value = d[key]
        if isinstance(value, dict):
            value1 = {}
            for keyIn in value:
                value1[".".join([key,keyIn])]=value[keyIn]
            flattenDict(value1, result)
        elif isinstance(value, (list, tuple)):   
            for indexB, element in enumerate(value):
                if isinstance(element, dict):
                    value1 = {}
                    index = 0
                    for keyIn in element:
                        newkey = ".".join([key,keyIn])        
                        value1[".".join([key,keyIn])]=value[indexB][keyIn]
                        index += 1
                    for keyA in value1:
                        flattenDict(value1, result)   
        else:
            result[key]=value
    return result

header=''
jd=''
#from local
import tail
p, f = tail.tail("/var/ossec/logs/archives/archives.log")
#for s in sys.stdin:
while True:
    if p.poll(1):
        s=f.stdout.readline()
        start = s.find('{')
        if s[len(s) -2] == '}':
            d=s[start:]
            d=d.strip()
            jd=json.loads(d)
            jd=flattenDict(jd)
            header= s[0:start] 
            #print  ("%s %s") % (header,json.dumps(jd))
            result=merge(parse_header(header),jd)
            post("nix",result)
        else:
            print s

