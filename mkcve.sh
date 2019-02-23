#!/bin/bash
bq mk --project_id=${projectid}  --description="cpedatai details https://nvd.nist.gov/products/cpe data from https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"  --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cve.schema  -t ${dataset}.cve
bq mk --project_id=${projectid}   --description="cvedata from https://nvd.nist.gov/vuln/data-feeds" --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cpe.schema  -t ${dataset}.cpe

