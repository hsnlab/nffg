# NFFG: Network Function Forwarding Graph

## Introduction

Python-based implementation of Network Function Forwarding Graph (NF-FG) used by ESCAPE.

## Requirements

* Python 2.7.6+
* NetworkX 1.11+

## Installation

Installation of dependencies on a Debian-based OS:
```bash
$ sudo apt update && sudo apt install python-pip
$ sudo -H pip install networkx
```
### Optional
To install the nffg files globally, use the following command in the project root:

```bash
$ sudo -H pip install --upgrade .
```

### Usage

Import main classes into a Python script:

```python
from nffg import *
```

A helper script is also installed globally for calculating ADD and DEL differences of two NFFG file:

```
$ nffg_diff.py -h
usage: nffg_diff.py [-h] old new

Calculate differences of NFFGs

positional arguments:
  old         path for old NFFG
  new         path for new NFFG

optional arguments:
  -h, --help  show this help message and exit
```

## License

Licensed under the Apache License, Version 2.0; see LICENSE file.

    Copyright (C) 2017 by
    János Czentye <janos.czentye@tmit.bme.hu>
    Balázs Németh <balazs.nemeth@tmit.bme.hu>
    Balázs Sonkoly <balazs.sonkoly@tmit.bme.hu>
