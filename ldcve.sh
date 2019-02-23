#!/bin/bash
python cveParser.py 
bq  --project=${projectid} load --replace --source_format=NEWLINE_DELIMITED_JSON ${dataset}.cpe\$`date +%Y%m%d` cpe.jsonl
bq  --project=forsettidev-167609 load --replace --source_format=NEWLINE_DELIMITED_JSON ${dataset}.cve\$`date +%Y%m%d` cve.jsonl
