# stix-to-misp
Converts a STIX Package into a MISP Event and publishes it to a MISP server

```
usage: stix-to-misp.py [-h] [-u MISP_URL] -k MISP_KEY [-v VERIFY_CERT]
                       [-d DISTRIBUTION] [-t TAGS] [-l LEVEL]
                       input_file

positional arguments:
  input_file            An AIS or CISCP XML STIX Package file

optional arguments:
  -h, --help            show this help message and exit
  -u MISP_URL, --misp-url MISP_URL
                        MISP server URL (defaults to https://localhost)
  -k MISP_KEY, --misp-key MISP_KEY
                        MISP API key
  -v VERIFY_CERT, --verify-cert VERIFY_CERT
                        Verify TLS certificate (defaults to true)
  -d DISTRIBUTION, --distribution DISTRIBUTION
                        MISP Event distribution (org, community, connected,
                        all, or a sharing group UUID)
  -t TAGS, --tags TAGS  MISP Event tags (use multiple times to set more than
                        one tag)
  -l LEVEL, --level LEVEL
                        MISP threat level (high, medium, low, or undefined -
                        defaults to low)
```
