from __future__ import print_function
import json
import os
import requests
from pprint import pprint
import gzip
import StringIO
import xmltodict
import re

def removeBareLists(adict):
    newdict={}
    for i in adict:
        if isinstance(adict[i],dict):
            adict[i] = removeBareLists(adict[i])
        if isinstance(adict[i],list) and len(adict[i])>0:
            if isinstance(adict[i][0],dict):
                for di in adict[i]:
                    adict[i] = removeBareLists(di)
            else:
                nl=[]
                for bi in adict[i]:
                    nl.append({i[:len(i)-1]:bi})
                adict[i]=nl
        newkey=i
        if i[:1] =="@" or i[:1] == "#":
            newkey=i[1:]
        if not BQVALIDFIELDNAME.match(newkey):
            newkey = BQINVALIDFIELDCHAR.sub("_",newkey)
        newdict[newkey] = adict[i]
    return newdict

cveuri = "https://nvd.nist.gov/vuln/data-feeds"
cpexmluri = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
spdxlicenses = "https://github.com/spdx/license-list-data/blob/master/json/licenses.json"
cpeout = "cpe.jsonl"
cveout = "cve.jsonl"

with open(cpeout, mode='wb') as cpeoutfh, open(cveout, mode='wb') as cveoutfh:
    BQVALIDFIELDNAME = re.compile("^[A-Za-z0-9_]+$")
    BQINVALIDFIELDCHAR = re.compile("[^A-Za-z0-9_]")

    r = requests.get(cpexmluri)
    if r.status_code == requests.codes.ok:
        cf = StringIO.StringIO(r.content)
        df = gzip.GzipFile(fileobj=cf)
        doc = xmltodict.parse(df.read())
        cpelist = doc["cpe-list"].pop("cpe-item",[])
        for icpe in cpelist:
            icpe["source"]=cpexmluri
            icpe = removeBareLists(icpe)
            ijson_data = json.JSONEncoder().encode(icpe)
            print(ijson_data, file=cpeoutfh)

    r = requests.get(cveuri)

    if r.status_code == requests.codes.ok:
        bits = r.text.split('.json.gz')
        jsongzipuris=[]
        for b in bits[:len(bits)-1]:
            bitty = b.split("<a href='")
            if len(bitty) >= 1:
                uriprefix = bitty[len(bitty)-1]
                jsongzipuris.append(uriprefix + ".json.gz")


    for jsonuri in jsongzipuris:
        r = requests.get(jsonuri)
        cf = StringIO.StringIO(r.content)
        df = gzip.GzipFile(fileobj=cf)
        jsonobj = json.loads(df.read())
        cvelist = jsonobj.pop("CVE_Items",[])
        jsonobj["uriSource"] = jsonuri
        for ji in cvelist:
            ji["source"] = jsonobj
            ji = removeBareLists(ji)
            ijson_data = json.JSONEncoder().encode(ji)
            print(ijson_data, file=cveoutfh)








