from __future__ import print_function
import json
import os
import requests
from pprint import pprint
import gzip
import StringIO
import xmltodict
import re
import bqtools
import copy

def removeBareLists(adict):
    newdict={}
    for i in adict:
        # fix reference sometimes being a dict not a llist
        if (i == "reference" or i == "title") and isinstance(adict[i],dict):
            adict[i] = [adict[i]]
        if isinstance(adict[i],dict):
            adict[i] = removeBareLists(adict[i])
        if isinstance(adict[i],list) and len(adict[i])>0:
            if isinstance(adict[i][0],dict):
                nl = []
                for di in adict[i]:
                    nl.append(removeBareLists(di))
                adict[i] = nl
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

cveuri = "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED"
cpexmluri = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
spdxlicenses = "https://github.com/spdx/license-list-data/blob/master/json/licenses.json"
cpeout = "cpe.jsonl"
cveout = "cve.jsonl"

with open(cpeout, mode='wb') as cpeoutfh, open(cveout, mode='wb') as cveoutfh,open("mkcve.sh", mode='wb+') as mkcve:
    BQVALIDFIELDNAME = re.compile("^[A-Za-z0-9_]+$")
    BQINVALIDFIELDCHAR = re.compile("[^A-Za-z0-9_]")
    resourcelist = []
    r = requests.get(cpexmluri)
    if r.status_code == requests.codes.ok:
        cf = StringIO.StringIO(r.content)
        df = gzip.GzipFile(fileobj=cf)
        doc = xmltodict.parse(df.read())
        cpelist = doc["cpe-list"].pop("cpe-item",[])
        template={}
        for icpe in cpelist:
            icpe["source"]=cpexmluri
            icpe = removeBareLists(icpe)
            template = bqtools.get_json_struct(icpe,template)
            ijson_data = json.JSONEncoder().encode(icpe)
            print(ijson_data, file=cpeoutfh)
        table = {
            "type": "TABLE",
            "location": os.environ["location"],
            "tableReference": {
                "projectId": os.environ["projectid"],
                "datasetId": os.environ["dataset"],
                "tableId": "cpe"
            },
            "timePartitioning": {
                "type": "DAY",
                "expirationMs": "94608000000"
            },
            "schema": {}
        }
        table["schema"]["fields"] = bqtools.get_bq_schema_from_json_repr(template)
        resourcelist.append(table)
        views = bqtools.gen_diff_views(os.environ["projectid"],
                                       os.environ["dataset"],
                                       "cpe",
                                       bqtools.create_schema(template))
        table = {
            "type": "VIEW",
            "tableReference": {
                "projectId": os.environ["projectid"],
                "datasetId": os.environ["dataset"],
                "tableId": "cpehead"
            },
            "view": {
                "query": bqtools.HEADVIEW.format(os.environ["projectid"], os.environ["dataset"], "cpe"),
                "useLegacySql": False

            }
        }
        resourcelist.append(table)
        for vi in views:
            table = {
                "type": "VIEW",
                "tableReference": {
                    "projectId": os.environ["projectid"],
                    "datasetId": os.environ["dataset"],
                    "tableId": vi["name"]
                },
                "view": {
                    "query": vi["query"],
                    "useLegacySql": False

                }
            }
            resourcelist.append(table)

    r = requests.get(cveuri)

    if r.status_code == requests.codes.ok:
        bits = r.text.split('.json.gz')
        jsongzipuris=[]
        for b in bits[:len(bits)-1]:
            bitty = b.split('<a href="')
            if len(bitty) >= 1:
                uriprefix = bitty[len(bitty)-1]
                jsongzipuris.append(uriprefix + ".json.gz")


    template = {}
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
            template = bqtools.get_json_struct(ji, template)
            ijson_data = json.JSONEncoder().encode(ji)
            print(ijson_data, file=cveoutfh)

    table = {
        "type": "TABLE",
        "location": os.environ["location"],
        "tableReference": {
            "projectId": os.environ["projectid"],
            "datasetId": os.environ["dataset"],
            "tableId": "cve"
        },
        "timePartitioning": {
            "type": "DAY",
            "expirationMs": "94608000000"
        },
        "schema": {}
    }
    table["schema"]["fields"] = bqtools.get_bq_schema_from_json_repr(template)
    resourcelist.append(table)
    views = bqtools.gen_diff_views(os.environ["projectid"],
                                   os.environ["dataset"],
                                   "cve",
                                   bqtools.create_schema(template))
    table = {
        "type": "VIEW",
        "tableReference": {
            "projectId": os.environ["projectid"],
            "datasetId": os.environ["dataset"],
            "tableId": "cvehead"
        },
        "view": {
            "query": bqtools.HEADVIEW.format(os.environ["projectid"], os.environ["dataset"], "cpe"),
            "useLegacySql": False

        }
    }
    resourcelist.append(table)
    for vi in views:
        table = {
            "type": "VIEW",
            "tableReference": {
                "projectId": os.environ["projectid"],
                "datasetId": os.environ["dataset"],
                "tableId": vi["name"]
            },
            "view": {
                "query": vi["query"],
                "useLegacySql": False

            }
        }
        resourcelist.append(table)

    bqtools.generate_create_schema(resourcelist, mkcve)




