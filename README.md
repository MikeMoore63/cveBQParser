# cveBQParser 
Noddy python cve and cpe parser that downoads cve and cpe data from NIST
Converts to jon newlline
Uploads into a day partitioned table(s) in Google Big Query each download is loaded into day partition of download
Provides support scripts to create tables and diwnloadsand load

config
setenvironment variables
export projectid=<google project id>
export dataset=<dataset to put tables in >

Script is python 2.7 based 
Requires googlle sdk installled including bq command line tool
To run install you must be llogged in and have created dataset for tables and views first and at lleast have editor rights on the dataset.
