#!/usr/bin/env python

# Connnect directly to Soltra's mongo instance and download indicators 

# Intel Framework expected input tab separated
# fields indicator       indicator_type  meta.source     meta.desc
# example
# 1.2.3.4 Intel::ADDR     source1 Sending phishing email  http://source1.com/badhosts/1.2.3.4
# a.b.com Intel::DOMAIN   source2 Name used for data exfiltration -

# Bro indicator_type https://www.bro.org/sphinx-git/scripts/base/frameworks/intel/main.bro.html#type-Intel::Type

from pymongo import MongoClient
# testing for valid IP address
# some indicators are labeled ipv4 when they are actually domains
#import ipaddress
import json
import argparse
from bson import json_util as ju

def format_indicator(indicator,ind_type,source,description):
    intel_map = { 'AddressObjectType' : 'Intel::ADDR',
            'DomainNameObjectType' : 'Intel::DOMAIN',
            'FileObjectType' : 'Intel::FILE_HASH',
            'URIObjectType' : 'Intel::URL' }

    new_line = '{}\t{}\t{}\t{}\n'.format(indicator,intel_map[ind_type],source,description)
    return new_line


parser = argparse.ArgumentParser()
parser.add_argument('mongo_ip', help='IP address of mongo db')
parser.add_argument('-p' ,'--port', default='27017', help='port mongo is listening on')
args = parser.parse_args()

# Auth turned off by default in mongo
client = MongoClient(args.mongo_ip, args.port)
db = client['inbox']
# stix collection is where all the indicators are stored
collection = db['stix']


# turns out this was the best source, needs to be changed and not hard coded
cursor = collection.find({"data.idns" : "http://threatcentral.io/"})

# Many possible locations of indicators after [data][api]
#  dict_keys(['id', 'observable_composition'])
#  dict_keys(['observable', 'id', 'title', 'indicator_types', 'description', 'confidence'])
#  dict_keys(['id', 'title', 'description'])
#  dict_keys(['observable', 'id', 'title', 'indicator_types', 'suggested_coas', 'description', 'confidence'])
#  ----- not worth the effort below this line right now -----
#  dict_keys(['id', 'title', 'observable', 'description', 'confidence'])
#  dict_keys(['timestamp', 'stix_header', 'indicators', 'id', 'version', 'observables'])
#  dict_keys(['observable', 'id', 'title', 'suggested_coas', 'description', 'confidence'])
#  dict_keys(['timestamp', 'stix_header', 'indicators', 'id', 'observables', 'courses_of_action', 'version'])
#  dict_keys(['timestamp', 'stix_header', 'indicators', 'id', 'observables', 'ttps', 'version'])
#  dict_keys(['observable', 'id', 'title', 'indicated_ttps', 'indicator_types', 'description', 'confidence'])


outfile = open('soltra_bro_intel','w')
outfile.write('# fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\n')
for x in range(0,cursor.count()):
    result = cursor.next()
    try:
        ind_type = result['data']['summary']['type']
        indicator = result['data']['summary']['value']
        if ind_type == 'FileObjectType' and indicator.count(':') == 1:
            indicator = indicator.split(':')[1].strip()

        
        if indicator != None:
            new_line = format_indicator(indicator,ind_type,'threatcentral','placeholder')
            outfile.write(new_line)
    except KeyError:
        pass

outfile.close()
