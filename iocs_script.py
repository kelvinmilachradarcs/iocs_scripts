#!/usr/bin/env python3

import argparse
import csv
import json
import re
import requests

def argumentsParser():
    # the main parser object with the script's usage in its description.
    parser = argparse.ArgumentParser(
        prog= './iocmatcher.py',
        description= f'This script allows the user to query APIs from multiple IOC databases and threat intelligence sources, such as AbuseIPDB, VirusTotal and others.'
    )

    # this args group is to determine the way to grab the API keys
    groupArgInputFile = parser.add_mutually_exclusive_group(required=True)
    # csv file option
    groupArgInputFile.add_argument(
        "--csv",
        type=str,
        action="store",
        help="use CSV file with API keys as input"
        )
    # json file option
    groupArgInputFile.add_argument(
        '--json',
        type=str,
        action="store",
        help="use JSON file with API keys as input"
        )

    # the ioc itself that the operator wants to check
    parser.add_argument(
        "ioc",
        type=str,
        action="store",
        help="IOC to be verified"
    )

    # return the input in order:
    # 1. api keys file type (csv or json)
    # 2. api keys file
    # 3. ioc type (domain, hash or ip address)
    # 4. ioc to be searched
    return vars(parser.parse_args())

def parsingCSVFile(csvfile):
    # doing error handling for file not found and wrong file type
    try:
        with open(csvfile, 'r') as f:
            keys = {rows[0]:rows[1] for rows in csv.reader(f)}
        f.close()
        return keys
    except FileNotFoundError:
        print(f'ERROR: no file "{csvfile}" was found\n')
        exit()
    except IndexError:
        print(f'ERROR: "{csvfile}" is not a CSV file\n')
        exit()

def parsingInputFile(args):
    if args["csv"] is not None:
        return parsingCSVFile(args["csv"])
    else:
        return parsingJSONFile(args["json"])

def parsingJSONFile(jsonfile):
    # doing error handling for file not found and wrong file type
    try:
        with open(jsonfile, 'r') as f:
            keys = json.loads(f.read())
            f.close()
            return keys
    except FileNotFoundError:
        print(f'ERROR: no file "{jsonfile}" was found\n')
        exit()
    except json.decoder.JSONDecodeError:
        print(f'ERROR: "{jsonfile}" is not a JSON file\n')
        exit()

def queryALL(keyValuePair, query):
    # if there's no API key, just return
    if keyValuePair[1] == '':
        return 

    # test if the query is a SHA256 or MD5 hash
    # SHA256 is 64 chars long and MD5 is 32 chars long
    if bool(re.search("^(?=(?:.{32}|.{64})$)[0-9a-fA-F]*$", query)): queryIsHash = True
    else: queryIsHash = False

    # switch-case for different providers
    if keyValuePair[0] == 'abuseipdb' and queryIsHash == False:
        return (keyValuePair[0], queryAbuseIpDb(keyValuePair[1], query))
    elif keyValuePair[0] == 'greynoise':
        return (keyValuePair[0], queryGreyNoise(keyValuePair[1], query))
    elif keyValuePair[0] == 'pulsedive':
        return (keyValuePair[0], queryPulsedive(keyValuePair[1], query))
    elif keyValuePair[0] == 'virustotal':
        return (keyValuePair[0], queryVirusTotal(keyValuePair[1], query))

def queryAbuseIpDb(key, query):
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={
                'Key': key,
                'Accept': 'application/json'
            },
            params={'ipAddress': query}
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return response.json()

def queryGreyNoise(key, query):
    try:
        response = requests.get(
            'https://api.greynoise.io/v3/community/'+query,
            headers={
                'accept': 'application/json',
                'key': key
            },
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return response.json()

def queryPulsedive(key, query):
    try:
        response = requests.get(
            'https://pulsedive.com/api/explore.php',
            params={
                'q': 'ioc='+query,
                'limit': '5',
                'pretty': '1',
                'key': key
            }
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return response.json()

def queryVirusTotal(key, query):
    try:
        response = requests.get(
            'https://www.virustotal.com/api/v3/search',
            headers={'x-apikey': key},
            params={'query': query}
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return response.json()

def main():
    results = []

    # invoking the next function related to the user input itself
    args = argumentsParser()
    apiKeys = parsingInputFile(args)

    # querying all services, passing key:value pair and the ioc to be queried
    for key in apiKeys.items():
        # creates a list of tuples
        # each tuple consists of two values: the service used (eg VT) and its response
        results.append(queryALL(key, args['ioc']))
    results = list(filter(None, results))


    # testing functions with print
    print(f'The arguments: {args}')
    print(f'The API keys: {apiKeys}')
    print(f'\nThe query results are: {results}')

if __name__ == '__main__':
    main()