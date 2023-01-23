# IOC query script

## Description

This Python script is used to perform an automated query to multiple cybersecurity vendors when looking into a potential IOC's reputation.

This way, the analyst can save time during analysis, which can be crucial when time is of the essence, or before manually searching for it is becoming too much cumbersome.

## Usage

```./iocmatcher.py [-h] (--csv CSV | --json JSON) ioc```

The scripts needs two components: a file (either CSV or JSON format) and the query itself (domain, hash or IP address). There are two example files for inputting the API keys needed for the script to work.

Example:
```./iocmatcher.py --csv api_keys.csv google.com```

Example of CSV file:
```
abuseipdb,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
greynoise,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
pulsedive,cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
virustotal,dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
```

Example of JSON file:
```
{
    "abuseipdb" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "greynoise" : "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "pulsedive" : "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "virustotal": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}
```