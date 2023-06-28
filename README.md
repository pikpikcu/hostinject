<h1 align="center">
  Hostinject
  <br>
</h1>

hostinject (Host Header Injection) Tool is a Python script that allows you to perform host header injection vulnerability testing on a target URL or a list of URLs. It injects various header values and checks for potential vulnerabilities.

## Features

- Injects custom headers with an attacker-controlled value
- Supports a list of target URLs from a file
- Allows customization of the maximum number of redirects
- Provides SSL verification option
- Outputs the results to the console and an optional output file

## Requirements

- Python 3.x
- Requests library (`pip install requests`)
- Colorama library (`pip install colorama`)

## Usage
```
python hostinject.py [-h] [-u URL] [-l LIST] [-w WORDLISTS] [-a ATTACKER]
[-o OUTPUT] [-r REDIRECT] [-s]

optional arguments:
-h, --help show this help message and exit
-u URL, --url URL Target URL
-l LIST, --list LIST List of target URLs
-w WORDLISTS, --wordlists WORDLISTS
Wordlist file containing header values
-a ATTACKER, --attacker ATTACKER
Attacker domain
-o OUTPUT, --output OUTPUT
Output file
-r REDIRECT, --redirect REDIRECT
Maximum number of redirects (default: 10)
-s, --ssl Enable SSL verification (default: False)
```

- Use either the `-u` or `-l` option to provide a single URL or a list of URLs, respectively.
- The `-w` option allows you to specify a file containing custom header values to be injected.
- The `-a` option sets the attacker domain for the injected headers.
- The `-o` option specifies the output file to store the results.
- The `-r` option allows you to customize the maximum number of redirects (default: 10).
- Use the `-s` option to enable SSL verification (default: False).

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
