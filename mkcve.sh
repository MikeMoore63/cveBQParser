#!/bin/bash
bq mk --project_id=${projectid}  --description="cpedatai details https://nvd.nist.gov/products/cpe data from https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"  --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cve.schema  -t ${dataset}.cve
bq mk --project_id=${projectid}   --description="cvedata from https://nvd.nist.gov/vuln/data-feeds" --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cpe.schema  -t ${dataset}.cpe

cat > /tmp/schema.$$.query <<'EOF'
#standardSQL
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
#standardSQL
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

cat > /tmp/schema.$$.query <<'EOF'
#standardSQL
SELECT
    REGEXP_EXTRACT(cpe_23_cpe23_item.name,r'^cpe:2.3:[^:]+:([^:]+):') AS vendor,
    REGEXP_EXTRACT(cpe_23_cpe23_item.name,r'^cpe:2.3:[^:]+:[^:]+:([^:]+):') AS product,
    REGEXP_EXTRACT(cpe_23_cpe23_item.name,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:([^\.:]+)\.') AS majorVersion,
    REGEXP_EXTRACT(cpe_23_cpe23_item.name,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:[^\.]+\.([^\.:]+)\.') AS minorVersion,
    REGEXP_EXTRACT(cpe_23_cpe23_item.name,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:[^\.]+\.[^\.]+\.([^\.:]+)\.') AS patchVersion,
    REGEXP_EXTRACT(cpe_23_cpe23_item.name,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:[^\.]+\.[^\.]+\.[^\.]+\.([^\.:]+)') AS patchMinorVersion,
    cpe_23_cpe23_item.name,
    title.text
FROM
    `zzprojectidzz.zzdatasetidzz.cpehead` 
EOF
cat /tmp/schema.$$.query | sed -e "s=zzprojectidzz=${projectid}=" | sed -e  "s=zzdatasetidzz=${dataset}=" > /tmp/schema.$$.query2
QUERY=`cat /tmp/schema.$$.query2`
bq  --project_id=${projectid} mk  --use_legacy_sql=false --view="${QUERY}"   --description='Latest download of cve data with vendor, product and versiona(vpv) as columns from cpe uri' ${dataset}.cpevpvhead

cat > /tmp/schema.$$.query <<'EOF'
#standardSQL
SELECT
    REGEXP_EXTRACT(cpe_match.cpe23Uri,r'^cpe:2.3:[^:]+:([^:]+):') AS vendor,
    REGEXP_EXTRACT(cpe_match.cpe23Uri,r'^cpe:2.3:[^:]+:[^:]+:([^:]+):') AS product,
    REGEXP_EXTRACT(cpe_match.cpe23Uri,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:([^\.:]+)\.') AS majorVersion,
    REGEXP_EXTRACT(cpe_match.cpe23Uri,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:[^\.]+\.([^\.:]+)\.') AS minorVersion,
    REGEXP_EXTRACT(cpe_match.cpe23Uri,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:[^\.]+\.[^\.]+\.([^\.:]+)\.') AS patchVersion,
    REGEXP_EXTRACT(cpe_match.cpe23Uri,r'^cpe:2.3:[^:]+:[^:]+:[^:]+:[^\.]+\.[^\.]+\.[^\.]+\.([^\.:]+)') AS patchMinorVersion,
    cpe_match.vulnerable,
    cpe_match.versionStartIncluding,
    cpe_match.versionStartExcluding,
    cpe_match.versionEndIncluding,
    cpe_match.versionEndExcluding,
    cve.CVE_data_meta.ID
FROM
    `zzprojectidzz.zzdatasetidzz.cvehead`
JOIN UNNEST(configurations.nodes) AS nodes
JOIN UNNEST(nodes.cpe_match) AS cpe_match
EOF
cat /tmp/schema.$$.query | sed -e "s=zzprojectidzz=${projectid}=" | sed -e  "s=zzdatasetidzz=${dataset}=" > /tmp/schema.$$.query2
QUERY=`cat /tmp/schema.$$.query2`
bq  --project_id=${projectid} mk  --use_legacy_sql=false --view="${QUERY}"   --description='Latest download of cve data with vendor, product and versiona(vpv) as columns from cpe uri' ${dataset}.cvevpvhead

cat > /tmp/schema.$$.query <<'EOF'
#standardSQL
SELECT
  DISTINCT vendor,
  product,
  REGEXP_EXTRACT(name,r'^(cpe:2.3:[^:]+:[^:]+:[^:]+):') AS cpeproductprefix
FROM
    `zzprojectidzz.zzdatasetidzz.cpevpvhead` 
EOF
cat /tmp/schema.$$.query | sed -e "s=zzprojectidzz=${projectid}=" | sed -e  "s=zzdatasetidzz=${dataset}=" > /tmp/schema.$$.query2
QUERY=`cat /tmp/schema.$$.query2`
bq  --project_id=${projectid} mk  --use_legacy_sql=false --view="${QUERY}"   --description='cpe products so has vendor product and cpe prefix to matchi to a product' ${dataset}.cpevpproducthead

cat > /tmp/schema.$$.query <<'EOF'
#standardSQL
SELECT
  DISTINCT vendor,
  product,
  majorVersion,
  concat(REGEXP_EXTRACT(name,r'^(cpe:2.3:[^:]+:[^:]+:[^:]+):'),':',majorVersion) AS cpeproductmvprefix
FROM
    `zzprojectidzz.zzdatasetidzz.cpevpvhead`
EOF
cat /tmp/schema.$$.query | sed -e "s=zzprojectidzz=${projectid}=" | sed -e  "s=zzdatasetidzz=${dataset}=" > /tmp/schema.$$.query2
QUERY=`cat /tmp/schema.$$.query2`
bq  --project_id=${projectid} mk  --use_legacy_sql=false --view="${QUERY}"   --description='cpe products major versions so has vendor product, major version  and cpe prefix to matchi to a product' ${dataset}.cpevpmvproducthead
rm /tmp/schema.$$.query /tmp/schema.$$.query2

