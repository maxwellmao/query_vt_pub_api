from __future__ import division
import sys
import os
import json
import urllib
import urllib2
import datetime
import time

def retrieving_file_scan_report(md5_list, api_key_list, save_path):
    url='https://www.virustotal.com/vtapi/v2/file/report'

    last_key_index=0
    
    print 'Total number of samples', len(md5_list)

    with open(save_path, 'w') as wp:

        for md5 in md5_list:
    
            while 1:
    
                try:
                    start_time=datetime.datetime.now()
    
                    para={'resource': md5, 'apikey': api_key_list[last_key_index]}
    
                    print para
                    
                    last_key_index+=1
    
                    if last_key_index>=len(api_key_list):
                        last_key_index=0
                    
                    data=urllib.urlencode(para)
            
                    req=urllib2.Request(url, data)
    
                    response=urllib2.urlopen(req)
    
                    result=response.read()
    
                    wp.write("[\"%s\", %s]\n" % (md5, result))
                
                except urllib2.URLError, e:
                    print e
    
                    continue
                except urllib2.HTTPError, e:
                    print e
                    continue
    
                finally:
                    end_time=datetime.datetime.now()
                    
                    cost_time=(end_time-start_time).seconds+(end_time-start_time).microseconds/1000000

                    print 'Query time:', cost_time, "s"

                    if cost_time<1.5:
                        time.sleep(1.5-cost_time)
    
                break


def load_md5_from_file(md5_file):
    md5_list=[]
    with open(md5_file) as fp:
        for line in fp.readlines():
            md5_list.append(line.strip().split()[0])
    return md5_list

def load_api_key_from_file(key_file):
    api_key_list=[]
    with open(key_file) as fp:
        for line in fp.readlines():
            api_key_list.append(line.strip())

    return api_key_list

def main(args):
    retrieving_file_scan_report(load_md5_from_file(args[0]), load_api_key_from_file(args[1]), args[2])

if __name__=='__main__':
    main(sys.argv[1:])
