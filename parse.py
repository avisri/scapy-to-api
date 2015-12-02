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
   
"""
2015 Dec 02 00:00:01 (trither-wsl2) any->/var/log/auth.log Dec  1 16:00:01 trither-wsl2 CRON[1053]: pam_unix(cron:session): session opened for user root by (uid=0)
2015 Dec 02 00:00:01 (edcripps-wsl) any->/var/log/auth.log Dec  1 16:00:01 edcripps-wsl CRON[6989]: pam_unix(cron:session): session opened for user root by (uid=0)
2015 Dec 02 00:00:01 (cnaylor-ltmr) any->/var/log/osqueryd.results.log {"name":"procs_on_internet","hostIdentifier":"cnaylor-ltmr.internal.salesforce.com","calendarTime":"Wed Dec  2 00:00:01 2015 UTC","unixTime":"1449014401","columns":{"family":"2","local_address":"10.33.14.161","local_port":"57576","name":"Google Chrome","pid":"881","protocol":"6","remote_address":"216.58.217.142","remote_port":"443"},"action":"added"}
2015 Dec 02 00:00:01 (cnaylor-ltmr) any->/var/log/osqueryd.results.log {"name":"procs_on_internet","hostIdentifier":"cnaylor-ltmr.internal.salesforce.com","calendarTime":"Wed Dec  2 00:00:01 2015 UTC","unixTime":"1449014401","columns":{"family":"2","local_address":"10.33.14.161","local_port":"57650","name":"Google Chrome","pid":"881","protocol":"6","remote_address":"38.127.167.50","remote_port":"443"},"action":"added"}
2015 Dec 02 00:00:01 (cnaylor-ltmr) any->/var/log/osqueryd.results.log {"name":"procs_on_internet","hostIdentifier":"cnaylor-ltmr.internal.salesforce.com","calendarTime":"Wed Dec  2 00:00:01 2015 UTC","unixTime":"1449014401","columns":{"family":"2","local_address":"10.33.14.161","local_port":"57577","name":"Google Chrome","pid":"881","protocol":"6","remote_address":"216.58.217.142","remote_port":"443"},"action":"added"}
"""
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
for s in sys.stdin:
    start = s.find('{')
    if s[len(s) -2] == '}':
        d=s[start:]
        d=d.strip()
        jd=json.loads(d)
        jd=flattenDict(jd)
        header= s[0:start] 
        #print  ("%s %s") % (header,json.dumps(jd))
        result=merge(parse_header(header),jd)
        #print "{0}".format(json.dumps(result)) 
	post("nix",result)
    else:
        print s

