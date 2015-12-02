#!/usr/bin/env python 

import json
import sys 
import re

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
    	print  ("%s %s") % (header,json.dumps(jd))
    else:
    	print s

