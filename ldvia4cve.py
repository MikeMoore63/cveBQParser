from __future__ import print_function
import json
import re
import pprint
import os
from jinja2 import Environment, select_autoescape, FileSystemLoader, TemplateNotFound

INVALIDBQFIELDCHARS = re.compile(r"[^a-zA-Z0-9_]")
HEADVIEW = """#standardSQL
SELECT
  *
FROM
  `{}.{}.{}`
WHERE
  _PARTITIONTIME = (
  SELECT
    MAX(_PARTITIONTIME)
  FROM
    `{}.{}.{}`)"""

def get_json_struct(jsonobj,template=None):
    if template is None:
        template = {}
    for key in jsonobj:
        newkey = INVALIDBQFIELDCHARS.sub("_", key)
        if jsonobj[key] is None:
            continue
        if newkey not in template:
            value = None
            if isinstance(jsonobj[key],bool):
                value = False
            elif isinstance(jsonobj[key], str):
                value = ""
            elif isinstance(jsonobj[key], unicode):
                value = u""
            elif isinstance(jsonobj[key], int):
                value = 0
            elif isinstance(jsonobj[key], float):
                value = 0.0
            elif isinstance(jsonobj[key], dict):
                value = get_json_struct(jsonobj[key])
            elif isinstance(jsonobj[key], list):
                if len(jsonobj[key]) == 0:
                    value = [{}]
                else:
                    if not isinstance(jsonobj[key][0],dict):
                        nv = []
                        for vali in jsonobj[key]:
                            nv.append({"value":vali})
                        jsonobj[key]=nv
                    value = [{}]
                    for li in jsonobj[key]:
                        value[0] = get_json_struct(li,value[0])
            template[newkey]=value
        else:
            if isinstance(jsonobj[key],type(template[newkey])):
                if isinstance(jsonobj[key],dict):
                    template[key] = get_json_struct(jsonobj[key],template[newkey])
                if isinstance(jsonobj[key],list):
                    if len(jsonobj[key]) != 0:
                        if not isinstance(jsonobj[key][0], dict):
                            nv = []
                            for vali in jsonobj[key]:
                                nv.append({"value": vali})
                            jsonobj[key] = nv
                    for li in jsonobj[key]:
                        template[newkey][0] = get_json_struct(li,template[newkey][0])
            else:
                raise Exception("Oops")
    return template

def clean_json_for_bq(anobject):
    newobj = {}
    if not isinstance(anobject, dict):
        raise Exception("Oops")
    for key in anobject:
        newkey = INVALIDBQFIELDCHARS.sub("_", key)
        value = anobject[key]
        if isinstance(value, dict):
            value = clean_json_for_bq(value)
        if isinstance(value, list):
            if len(value) != 0:
                if not isinstance(value[0], dict):
                    nv = []
                    for vali in value:
                        nv.append({"value": vali})
                    value = nv
                valllist = []
                for vali in value:
                    vali = clean_json_for_bq(vali)
                    valllist.append(vali)
                value = valllist
        newobj[newkey] = value
    return newobj

def write_cve_json_data(cves,key,fh,template):
    for cve,data in cves.items():
        ref = []
        if not isinstance(template["references"],list):
            ref={}
        jsonout = {"cveid": cve, "references": ref}
        for refkey in data:
            newkey = INVALIDBQFIELDCHARS.sub("_", refkey)
            if newkey == key:
                if isinstance(data[refkey],list):
                    for anitem in data[refkey]:
                        jsonout["references"].append(clean_json_for_bq(anitem))
                else:
                    jsonout["references"] = clean_json_for_bq(data[refkey])
        if len(jsonout["references"]) > 0:
            print(json.JSONEncoder().encode(jsonout),file=fh)
    return
def get_bq_schema_from_json_repr(jsondict):
    fields = []
    for key,data in jsondict.items():
        field = {"name":key}
        if isinstance(data, bool):
            field["type"]="BOOLEAN"
            field["mode"] = "NULLABLE"
        elif isinstance(data, str):
            field["type"] = "STRING"
            field["mode"] = "NULLABLE"
        elif isinstance(data, unicode):
            field["type"] = "STRING"
            field["mode"] = "NULLABLE"
        elif isinstance(data, int):
            field["type"] = "INTEGER"
            field["mode"] = "NULLABLE"
        elif isinstance(data, float):
            field["type"] = "FLOAT"
            field["mode"] = "NULLABLE"
        elif isinstance(data, dict):
            field["type"] = "RECORD"
            field["mode"] = "NULLABLE"
            field["fields"] = get_bq_schema_from_json_repr(data)
        elif isinstance(data, list):
            field["type"] = "RECORD"
            field["mode"] = "REPEATED"
            field["fields"] = get_bq_schema_from_json_repr(data[0])
        fields.append(field)
    return fields

cves = json.loads(open("../VIA4CVE/VIA4CVE-feed.json").read())
template = {}
pp = pprint.PrettyPrinter(width=80)
for key,data in cves["cves"].items():
    template = get_json_struct(data,template)

newtemplate = {}
for key in template:
    newtemplate[key] = {"cveid":"","references":template[key]}


jinjaenv = Environment(
                loader=FileSystemLoader("./templates"),
                autoescape=select_autoescape(['html', 'xml']),
                extensions=['jinja2.ext.do', 'jinja2.ext.loopcontrols']
            )

# generate a bash script to create tables of right schema
with open("mkvia4cveschema.sh", mode='wb+') as fh, open("ldvia4cve.sh", mode='wb+') as lfh :
    # generate table creation scripts
    objtemplate = jinjaenv.get_template("bqschema.in")
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
        table["schema"]["fields"] = get_bq_schema_from_json_repr(data)
        resourcelist.append(table)
        table = {
            "type": "VIEW",
            "tableReference": {
                "projectId": os.environ["projectid"],
                "datasetId": os.environ["dataset"],
                "tableId": key +"head"
            },
            "view": {
                "query":HEADVIEW.format(os.environ["projectid"],os.environ["dataset"],key,os.environ["projectid"],os.environ["dataset"],key),
                "useLegacySql":False

            }
        }
        resourcelist.append(table)
        print(
            'bq  --project={} load --replace --source_format=NEWLINE_DELIMITED_JSON {}.{}\$`date +%Y%m%d` {}.jsonl'.format(
                os.environ["projectid"], os.environ["dataset"], key, key), file=lfh)

    output = objtemplate.render(resourcelist=resourcelist)
    print(output.encode('utf-8'), file=fh)


for key,data in newtemplate.items():
    with open("{}.jsonl".format(key), mode='wb+') as fh:
        write_cve_json_data(cves["cves"],key,fh,template=data)


