# cveBQParser 
Noddy python cve and cpe parser that downoads cve and cpe data from NIST
Converts to json newline
Uploads into a day partitioned table(s) in Google Big Query each download is loaded into day partition of download
Provides support scripts to create tables and downloads and load

config

setenvironment variables

export projectid=&lt;google project id>

export dataset=&lt;dataset to put tables in >

Script is python 2.7 based 
Requires google sdk installled including bq command line tool
To run install you must be llogged in and have created dataset for tables and views first and at lleast have editor rights on the dataset.

Once environment variables set and logged in basic install is (this uses the bq command line tool to create tables and is bash based)

bash ./mkcve.sh

To download parses and load daat into current dates partition after environment variables set is  (this invokes the python script and once local files invokes bq command line to load the data)

bash ./ldcve.sh

Or alternatively I made the data I have loaded publicly readable here https://bigquery.cloud.google.com/dataset/forsettidev-167609:nistcve
