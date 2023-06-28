<h1 align="center">
  Hostinject
  <br>
</h1>

hostinject (Host Header Injection) Tool is a Python script that allows you to perform host header injection vulnerability testing on a target URL or a list of URLs. It injects various header values and checks for potential vulnerabilities.

## Features

- Host Header Injection scanning on single URLs or a list of URLs
- Customizable header values using a wordlist file
- Option to specify the attacker domain
- Ability to set the maximum number of redirects
- SSL verification enable/disable option
- Support for various HTTP methods
- Random User-Agent selection from a wordlist file or custom User-Agent string
- Verbose mode for detailed output
- Support for request body in POST requests
- Support Proxy HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5

## Installation
***Requirements***
- Python 3.x

1. Clone the repository:
   ```shell
   git clone https://github.com/example/hostinject.git
   cd hostinject
   pip install -r requirements.txt
   python3 hostinject.py
   ```
   
## Usage
```shell
usage: hostinject.py [-h] [-u URL] [-l LIST] [-w WORDLISTS] [-a ATTACKER] [-o OUTPUT] [-r REDIRECT] [-s] [-x METHOD] [-b BODY] [-U USER_AGENT] [-v]

Hostinject (Host Header Injection Scanners)

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL
  -l LIST, --list LIST  List of target URLs
  -w WORDLISTS, --wordlists WORDLISTS
                        Wordlist file containing header values
  -a ATTACKER, --attacker ATTACKER
                        Attacker domain
  -o OUTPUT, --output OUTPUT
                        Output file
  -r REDIRECT, --redirect REDIRECT
                        Maximum number of redirects
  -s, --ssl             Enable SSL verification
  -x METHOD, --method METHOD
                        HTTP method
  -b BODY, --body BODY  Body request as string or file
  -U USER_AGENT, --user-agent USER_AGENT
                        User-Agent string or wordlist file
  -p PROXY, --proxy PROXY
                        Proxy server (e.g., http://proxy.example.com:8080 or socks5://proxy.example.com:1080)
  -v, --verbose         Enable verbose mode
```

- `-u, --url`: Target URL to scan.
- `-l, --list`: File containing a list of target URLs to scan.
- `-w, --wordlists`: Wordlist file containing header values (default: predefined wordlist).
- `-a, --attacker`: Attacker domain to be injected (default: attacker.com).
- `-o, --output`: Output file to save the scan results.
- `-r, --redirect`: Maximum number of redirects to follow (default: 10).
- `-s, --ssl`: Enable SSL verification.
- `-x, --method`: HTTP method to use (default: GET).
- `-b, --body`: Request body as a string or file for POST requests.
- `-U, --user-agent`: User-Agent string or wordlist file (default: random User-Agent from predefined list).
- `-v, --verbose`: Enable verbose mode.

## Examples

***Inject host headers on a single URL:***

python3 hostinject.py -u https://example.com -w headers.txt -a attacker.com -o results.txt


***Inject host headers on a list of URLs:***

python hostinject.py -l urls.txt -w headers.txt -a attacker.com -o results.txt

## Notes

- This tool is intended for security testing purposes only. Use it responsibly and with proper authorization.
- Make sure to comply with the target website's terms of service and legal requirements before performing any tests.

## License

This project is licensed under the [MIT License](LICENSE).
