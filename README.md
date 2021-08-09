# Hitachi Data Instance Director REST 1.X SDK for Python  

## Table of Contents
- [About](#about)
- [Requirements](#requirements)
- [Quick Start Guide](#quick-start-guide)
- [Run SDK Samples](#run-sdk-samples)
- [API Documentation](#api-documentation)
- [Files](#files)

## About
This module is designed to provide a simple interface for interacting
with HDID or Ops Center Protector. It has not been tested against Ops
Center Protector, but based on the REST API documentation they look the
same.

The samples below have been developed to work with python 3.6+

## Requirements
This module requires the use of Python 3.6 or later and the third-party
library "requests".

This module has only been tested with HDID versions 6.X.

## Quick Start Guide

### Prepare a Python Development Environment

We recommend you to install latest [Python](http://docs.python-guide.org/en/latest/starting/installation/) and
[pip](https://pypi.python.org/pypi/pip/) on your system.

### Installing Required Python Packages

Always good to upgrade to the latest pip and requests.

```cmd
pip install --upgrade pip requests
```

### Connect to HDID or Ops Center Protector

```python
import json
import urllib3
from hdid import HDID

# Disable the secure connection warning for demo purpose.
# This is not recommended in a production environment.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Connect to a HDID Server using username and password.
session = HDID("localhost", username=admin,
                password=password123, space="master",
                dest_node="master")

```

## Run SDK Samples

In this section I will walk you through the steps to run sample code.


# List all Hitachi Hardware Block Nodes inside the HDID environment
```python
hdw_nodes = session.list_hdw_nodes()
jsonstring = json.dumps(hdw_nodes, indent=2)
print(jsonstring)
```

Sample Output:
```shell
{
  [
    {
      "id": "HBN_0A@00-203944-B73B4A-4B17A2-51C703[0-1-A4]",
      "timestamp": "2021-01-07T20:24:41Z",
      "name": "HBN_0A",
      "hostNode": "array01@00-EABA84-BDF3A4-41E081-9039B1[1-1-A]",
      "dataSet": [
        {
          "lDev": "0x0000"
        },
        {
          "lDev": "0x0001"
        }
      ],
      "nodeType": "HardwareNodeBlock",
      "excludedDataSet": []
    },
    {
      "id": "HBN_0B@00-B004EA-E75D9B-4291A3-AF862E[0-1-A5]",
      "timestamp": "2021-01-07T20:24:55Z",
      "name": "HBN_0B",
      "hostNode": "array01@00-EABA84-BDF3A4-41E081-9039B1[1-1-A]",
      "dataSet": [
        {
          "lDev": "0x0002"
        },
        {
          "lDev": "0x0003"
        }
      ],
      "nodeType": "HardwareNodeBlock",
      "excludedDataSet": []
    }
  ]
}
```

# Get a Hitachi Hardware Block Node
```python
hdw_node = session.get_hdw_node("HBN_0D@00-B004EA-E75D9B-4291A3-AF862E[0-1-A5]")
jsonstring = json.dumps(hdw_node, indent=2)
print(jsonstring)
```

Sample Output:
```shell
{
  "id": "HBN_0A@00-203944-B73B4A-4B17A2-51C703[0-1-A4]",
  "timestamp": "2021-01-07T20:24:41Z",
  "name": "HBN_0A",
  "hostNode": "array01@00-EABA84-BDF3A4-41E081-9039B1[1-1-A]",
  "dataSet": [
    {
      "lDev": "0x0000"
    },
    {
      "lDev": "0x0001"
    }
  ],
  "nodeType": "HardwareNodeBlock",
  "excludedDataSet": []
}
```

# Update a Hitachi Hardware Block Node
```python
hbn_id = "HBN_0A@00-203944-B73B4A-4B17A2-51C703[0-1-A4]"
host_node_id = "array01@00-EABA84-BDF3A4-41E081-9039B1[1-1-A]"
data = {
            "dataSet": [
                {"lDev": "0x0000"},
                {"lDev": "0x0001"},
                {"lDev": "0x0004"}
            ]
        }

session.set_hdw_node(hbn_id, host_node_id, **data)
```

# Create a Hitachi Hardware Block Node
```python
name = "HBN_0D"
host_node_id = "array01@00-EABA84-BDF3A4-41E081-9039B1[1-1-A]"
data = {
            "dataSet": [
                {"lDev": "0x0005"},
                {"lDev": "0x0006"},
                {"lDev": "0x0007"}
            ]
        }

session.create_hdw_node(name, host_node_id, **data)
```


## API Documentation

### HDID API Documentation

* [HDID 6.9.x (latest)](https://knowledge.hitachivantara.com/Documents/Data_Protection/Ops_Center_Protector/6.9.x/Data_Instance_Director_6.9.x_Documentation_Library)
* [Ops Center Protector 7.2.x (latest)](https://knowledge.hitachivantara.com/Documents/Data_Protection/Ops_Center_Protector/7.2.x/Ops_Center_Protector_7.2.x_Documentation_Library)


## Files

* hdid/ -- Contains module.
* README.md -- This document.
