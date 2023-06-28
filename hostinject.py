#!/usr/bin/python3

import argparse
import os
from colorama import init, Fore
import requests

init(autoreset=True)

DEFAULT_WORDLIST = [
    'Host',
    'Max-Forwards',
    'Origin',
    'Proxy-Authorization',
    'Range',
    'Referer',
    'Upgrade',
    'User-Agent',
    'X-Forwarded-For',
    'X-Forwarded-Host'
]

DEFAULT_ATTACKER = 'attacker.com'
DEFAULT_REDIRECTS = 10
DEFAULT_SSL = False

def inject_host_header(url, wordlists, attacker, output_file, max_redirects, use_ssl):
    try:
        if wordlists:
            with open(wordlists, 'r') as file:
                headers = file.readlines()
        else:
            headers = DEFAULT_WORDLIST

        for header in headers:
            headers_dict = {
                'Host': url.split('/')[2],
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                header.strip(): attacker
            }

            response = requests.get(url, headers=headers_dict, allow_redirects=max_redirects, verify=use_ssl)

            if attacker.lower() in response.headers or attacker.lower() in response.content.decode('utf-8').lower():
                result = Fore.GREEN + '[Vulnerability] ' + Fore.YELLOW + '[Header: ' + header.strip() + '] ' + Fore.WHITE + url
                print(result)
                if output_file:
                    with open(output_file, 'a') as output:
                        output.write(result + '\n')
                break
        else:
            result = Fore.RED + '[No Vulnerability] ' + Fore.WHITE + url
            print(result)
            if output_file:
                with open(output_file, 'a') as output:
                    output.write(result + '\n')

    except requests.exceptions.TooManyRedirects:
        print(Fore.MAGENTA + '[Error] [Exceeded {} redirects]'.format(max_redirects))
    except requests.exceptions.SSLError as e:
        error_message = str(e)
        ssl_error = error_message.split(': ')[-1] if ': ' in error_message else error_message
        print(Fore.MAGENTA + '[Error] [SSLError] {}'.format(ssl_error))
    except requests.exceptions.RequestException as e:
        print(Fore.MAGENTA + '[Error] [{}] {}'.format(type(e).__name__, e))

def main():
    parser = argparse.ArgumentParser(description='Hostinject (Host Header Injection Scanners)')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-l', '--list', help='List of target URLs')
    parser.add_argument('-w', '--wordlists', help='Wordlist file containing header values')
    parser.add_argument('-a', '--attacker', help='Attacker domain')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-r', '--redirect', type=int, default=DEFAULT_REDIRECTS, help='Maximum number of redirects')
    parser.add_argument('-s', '--ssl', action='store_true', default=DEFAULT_SSL, help='Enable SSL verification')

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error('Please provide either a single URL or a list of URLs.')

    if args.url and args.list:
        parser.error('Please provide either a single URL or a list of URLs, not both.')

    if not args.attacker:
        args.attacker = DEFAULT_ATTACKER

    if args.url:
        inject_host_header(args.url, args.wordlists, args.attacker, args.output, args.redirect, args.ssl)

    elif args.list:
        if os.path.isdir(args.list):
            parser.error('Error: The provided list argument is a directory.')
        try:
            with open(args.list, 'r') as file:
                urls = file.readlines()
                for url in urls:
                    inject_host_header(url.strip(), args.wordlists, args.attacker, args.output, args.redirect, args.ssl)
        except FileNotFoundError:
            print('Error: File not found:', args.list)


if __name__ == '__main__':
    main()
