#!/usr/bin/env python

import subprocess
import select
def tail( filename="/var/ossec/logs/archives/archives.log"):
    try:
        f= subprocess.Popen(['tail', '-f', filename], stdout=subprocess.PIPE)
        p = select.poll()
        p.register(f.stdout)
        #TODO: trap and close file handle
        return p,f
    except (OSError, ValueError):
        pass    # TODO: handle errors
        return None,None


if __name__ == '__main__':
    p, f = tail()
    while True:
        if p.poll(1):
            print f.stdout.readline()

