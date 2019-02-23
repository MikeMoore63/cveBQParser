#!/bin/bash
bq mk --project_id=${projectid}  --description="cpedatai details https://nvd.nist.gov/products/cpe data from https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"  --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cve.schema  -t ${dataset}.cve
bq mk --project_id=${projectid}   --description="cvedata from https://nvd.nist.gov/vuln/data-feeds" --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cpe.schema  -t ${dataset}.cpe

cat > /tmp/schema.$$.query <<'EOF'
#standardySQL
SELECT
  *
FROM
  `zzprojectidzz.zzdatasetidzz.cpe`
WHERE
  _PARTITIONTIME = (
  SELECT
    MAX(_PARTITIONTIME)
  FROM
    `zzprojectidzz.zzdatasetidzz.cpe`)
EOF
cat /tmp/schema.$$.query | sed -e "s=zzprojectidzz=${projectid}=" | sed -e  "s=zzdatasetidzz=${dataset}=" > /tmp/schema.$$.query2
QUERY=`cat /tmp/schema.$$.query2`
bq  --project_id=${projectid} mk  --use_legacy_sql=false --view="${QUERY}"   --description='Latest download of cpe data' ${dataset}.cpehead

cat > /tmp/schema.$$.query <<'EOF'
#standardySQL
SELECT
  *
FROM
  `zzprojectidzz.zzdatasetidzz.cve`
WHERE
  _PARTITIONTIME = (
  SELECT
    MAX(_PARTITIONTIME)
  FROM
    `zzprojectidzz.zzdatasetidzz.cve`)
EOF
cat /tmp/schema.$$.query | sed -e "s=zzprojectidzz=${projectid}=" | sed -e  "s=zzdatasetidzz=${dataset}=" > /tmp/schema.$$.query2
QUERY=`cat /tmp/schema.$$.query2`
bq  --project_id=${projectid} mk  --use_legacy_sql=false --view="${QUERY}"   --description='Latest download of cpe data' ${dataset}.cvehead
rm /tmp/schema.$$.query /tmp/schema.$$.query2

