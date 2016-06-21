# Retrieving detection results from VirusTotal via its public API

- retrieving detection results of files identified by their md5 values
- since there are limitations on quotas for each apikey, I suggest you register a bunch of apikeys
- usage: 
    $ python query_pub_api.py list_of_querying_md5 list_of_owned_apikey save_path

