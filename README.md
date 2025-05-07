# DynamicWebScanning

This script scans for POST message listeners and broken links generated dynamically by websites. Many recon tools rely on fetching pages via GET requests for static analysis. While this approach is efficient when scanning against a large number of targets, it might miss valuable information loaded during a session.

### Usage
```nroff
usage: main.py [-h] [-u URL] [-t THREADS] [-d] [urls]

dynamic analysis of web pages

positional arguments:
  urls                  accepts list of URLs via file or STDIN

options:
  -h, --help            show this help message and exit
  -u, --url URL         Scan single URL
  -t, --threads THREADS
                        Thread count defaults to 1
  -d, --debug           Enable debug logging
```
### Examples
```
chmod +x main.py
```
```
cat subdomains.txt | main.py | jq
```
```
main.py subdomains.txt
```
```
main.py -u host.com
```

![](dynamic_webscan.png)
