#!/bin/bash
bq mk --project_id=${projectid}   --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cve.schema  -t ${dataset}.cve
bq mk --project_id=${projectid}   --time_partitioning_type=DAY --time_partitioning_expiration=94608000000000 --schema cpe.schema  -t ${dataset}.cpe

