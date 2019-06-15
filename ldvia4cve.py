from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
import json
import pprint
import os
import bqtools


def write_cve_json_data(cves,key,fh,template):
    for cve,data in cves.items():
        ref = []
        if not isinstance(template["references"],list):
            ref={}
        jsonout = {"cveid": cve, "references": ref}
        for refkey in data:
            newkey = bqtools.INVALIDBQFIELDCHARS.sub("_", refkey)
            if newkey == key:
                if isinstance(data[refkey],list):
                    for anitem in data[refkey]:
                        jsonout["references"].append(bqtools.clean_json_for_bq(anitem))
                else:
                    jsonout["references"] = bqtools.clean_json_for_bq(data[refkey])
        if len(jsonout["references"]) > 0:
            print(bqtools.BQJsonEncoder().encode(jsonout),file=fh)
    return


cves = json.loads(open("../VIA4CVE/VIA4CVE-feed.json").read())
template = {}
pp = pprint.PrettyPrinter(width=80)
for key,data in cves["cves"].items():
    template = bqtools.get_json_struct(data,template)

newtemplate = {}
for key in template:
    newtemplate[key] = {"cveid":"","references":template[key]}



# generate a bash script to create tables of right schema
with open("mkvia4cveschema.sh", mode='wb+') as fh, open("ldvia4cve.sh", mode='wb+') as lfh :
    # generate table creation scripts
    resourcelist=[]
    for key,data in newtemplate.items():
        table = {
               "type":"TABLE",
               "location":os.environ["location"],
               "tableReference":{
                   "projectId": os.environ["projectid"],
                   "datasetId": os.environ["dataset"],
                   "tableId": key
               },
               "timePartitioning":{
                   "type": "DAY",
                   "expirationMs": "94608000000"
               },
               "schema": {}
        }
        table["schema"]["fields"] = bqtools.get_bq_schema_from_json_repr(data)
        resourcelist.append(table)
        views = bqtools.gen_diff_views(os.environ["projectid"],
                               os.environ["dataset"],
                               key,
                               bqtools.create_schema(data))
        table = {
            "type": "VIEW",
            "tableReference": {
                "projectId": os.environ["projectid"],
                "datasetId": os.environ["dataset"],
                "tableId": key +"head"
            },
            "view": {
                "query":bqtools.HEADVIEW.format(os.environ["projectid"],os.environ["dataset"],key),
                "useLegacySql":False

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

        print(
            'bq  --project={} load --replace --source_format=NEWLINE_DELIMITED_JSON {}.{}\$`date +%Y%m%d` {}.jsonl'.format(
                os.environ["projectid"], os.environ["dataset"], key, key), file=lfh)

    bqtools.generate_create_schema(resourcelist, fh)


for key,data in newtemplate.items():
    with open("{}.jsonl".format(key), mode='wb+') as fh:
        write_cve_json_data(cves["cves"],key,fh,template=data)


