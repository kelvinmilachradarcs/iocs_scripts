#!/usr/bin/env python3

import argparse
import csv
import json
import re

import dns.resolver
import requests


def argumentsParser():
    # the main parser object with the script's usage in its description.
    parser = argparse.ArgumentParser(
        prog="./iocmatcher.py",
        description=f"This script allows the user to query APIs from multiple IOC databases and threat intelligence sources, such as AbuseIPDB, VirusTotal and others.",
    )

    # this args group is to determine the way to grab the API keys
    groupArgInputFile = parser.add_mutually_exclusive_group(required=True)
    # csv file option
    groupArgInputFile.add_argument(
        "--csv", type=str, action="store", help="use CSV file with API keys as input"
    )
    # json file option
    groupArgInputFile.add_argument(
        "--json", type=str, action="store", help="use JSON file with API keys as input"
    )

    # the ioc itself that the operator wants to check
    parser.add_argument("ioc", type=str, action="store", help="IOC to be verified")

    # return the input in order:
    # 1. api keys file type (csv or json)
    # 2. api keys file
    # 3. ioc type (domain, hash or ip address)
    # 4. ioc to be searched
    return vars(parser.parse_args())


def parsingCSVFile(csvFile):
    # doing error handling for file not found and wrong file type
    try:
        with open(csvFile, "r") as f:
            keys = {rows[0]: rows[1] for rows in csv.reader(f)}
        f.close()
        return keys
    except FileNotFoundError:
        print(f'ERROR: no file "{csvFile}" was found\n')
        exit()
    except IndexError:
        print(f'ERROR: "{csvFile}" is not a CSV file\n')
        exit()


def parsingInputFile(args):
    if args["csv"] is not None:
        return parsingCSVFile(args["csv"])
    else:
        return parsingJSONFile(args["json"])


def parsingJSONFile(jsonFile):
    # doing error handling for file not found and wrong file type
    try:
        with open(jsonFile, "r") as f:
            keys = json.loads(f.read())
            f.close()
            return keys
    except FileNotFoundError:
        print(f'ERROR: no file "{jsonFile}" was found\n')
        exit()
    except json.decoder.JSONDecodeError:
        print(f'ERROR: "{jsonFile}" is not a JSON file\n')
        exit()


# function to call all query functions
def queryALL(keyValuePair, query):
    # if there's no API key, just return
    if keyValuePair[1] == "":
        return (keyValuePair[0], None)

    # test if the query is a SHA256 or MD5 hash
    # SHA256 is 64 chars long and MD5 is 32 chars long
    if bool(re.search("^(?=(?:.{32}|.{64})$)[0-9a-fA-F]*$", query)):
        is_hash = True
    else:
        is_hash = False

    # switch-case for different providers

    # AbuseIPDB does not query for hashes so, in that case, it is not used
    if keyValuePair[0] == "abuseipdb" and is_hash == False:
        return (keyValuePair[0], queryAbuseIpDb(keyValuePair[1], query))
    elif keyValuePair[0] == "greynoise":
        return (keyValuePair[0], queryGreyNoise(keyValuePair[1], query))
    elif keyValuePair[0] == "pulsedive":
        return (keyValuePair[0], queryPulsedive(keyValuePair[1], query))
    elif keyValuePair[0] == "virustotal":
        return (keyValuePair[0], queryVirusTotal(keyValuePair[1], query))


# function to query AbuseIPDB
def queryAbuseIpDb(key, query):
    # if a domain is supplied, resolve it to an ip address
    if (
        bool(
            re.search(
                "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                query,
            )
        )
        is not True
    ):
        query = dns.resolver.resolve(query, "A")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": query},
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return resultsAbuseIPDB(response.json())


# function to query GreyNoise
def queryGreyNoise(key, query):
    try:
        response = requests.get(
            "https://api.greynoise.io/v3/community/" + query,
            headers={"accept": "application/json", "key": key},
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return response.json()


# function to query Pulsedive
def queryPulsedive(key, query):
    try:
        response = requests.get(
            "https://pulsedive.com/api/info.php",
            params={"indicator": query, "pretty": "1", "key": key},
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return resultsPulsedive(response.json())


# function to query VirusTotal
def queryVirusTotal(key, query):
    try:
        response = requests.get(
            "https://www.virustotal.com/api/v3/search",
            headers={"x-apikey": key},
            params={"query": query},
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return None
    else:
        return resultsVirusTotal(response.json())


# function to parse abuseipdb results and create a risk value
def resultsAbuseIPDB(results):

    if results["data"]["abuseConfidenceScore"] >= 70.0:
        print("high risk")
    elif 40 <= results["data"]["abuseConfidenceScore"] < 70:
        print("medium risk")
    elif 10 <= results["data"]["abuseConfidenceScore"] < 40:
        print("low risk")
    else:
        print("negligible/no risk")
    return {"abuseConfidenceScore": results["data"]["abuseConfidenceScore"]}


# function to parse pulsedive results and get the risk value
def resultsPulsedive(results):
    if "error" in results:
        return None
    else:
        return f"{results['risk']} risk"


# function to parse the VT results to get only the malicious/suspicious/etc flags
def resultsVirusTotal(results):
    metrics = results["data"][0]["attributes"]["last_analysis_stats"]

    x1 = metrics["malicious"] + metrics["suspicious"]
    x2 = (
        metrics["malicious"]
        + metrics["suspicious"]
        + metrics["harmless"]
        + metrics["undetected"]
    )

    y = (x1 / x2) * 100

    if y >= 70.0:
        print("high risk")
    elif 40 <= y < 70:
        print("medium risk")
    elif 10 <= y < 40:
        print("low risk")
    else:
        print("negligible/no risk")

    return results["data"][0]["attributes"]["last_analysis_stats"]


def main():

    results = []

    # invoking the next function related to the user input itself
    args = argumentsParser()
    apiKeys = parsingInputFile(args)

    # querying all services, passing key:value pair and the ioc to be queried
    for key in apiKeys.items():
        # creates a list of tuples. each tuple consists of two values: the service
        # used - eg 'virustotal'- and its response.
        # the tuple consists of (string, response)
        results.append(queryALL(key, args["ioc"]))

    # filter results with None
    results = [result for result in results if result[1] is not None]

    # final print
    print(f"\n\nThe query results are: {results}")


if __name__ == "__main__":
    main()
