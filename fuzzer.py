import argparse
import requests
import httpx
import sys

def create_fuzzed_urls(base_url, wordlist, fuzz_marker="FUZZ"):
    """
    Generates fuzzed URLs by replacing a marker with words from a wordlist.

    Args:
        base_url (str): The URL to fuzz, containing a `fuzz_marker` placeholder.
        wordlist (list): A list of words to use for fuzzing.
        fuzz_marker (str, optional): The placeholder in the base_url to replace.
                                     Defaults to "FUZZ".

    Returns:
        generator: A generator that yields fuzzed URLs.
    """
    for word in wordlist:
        yield base_url.replace(fuzz_marker, word)

def fuzz_url(url, method="GET", headers={}, timeout=10, verbose=False):
    """
    Sends an HTTP request to a fuzzed URL and returns the response.

    Args:
        url (str): The fuzzed URL to request.
        method (str, optional): The HTTP method to use (GET, POST, etc.).
                                 Defaults to "GET".
        headers (dict, optional): Custom headers to include in the request.
                                  Defaults to {}.
        timeout (int, optional): The request timeout in seconds. Defaults to 10.
        verbose (bool, optional): If True, prints verbose output including
                                  request details and full response headers.

    Returns:
        requests.Response or None: The response object if the request is successful,
                                    otherwise None.
    """
    try:
        if verbose:
            print(f"\n\033[1;97m[*] Requesting: \033[1;96m{url} \033[1;93m[{method}]\n\033[0m")

        response = requests.request(method, url, headers=headers, timeout=timeout)

        if verbose:
            print(f"[*] Response Status Code: {response.status_code}")
            print("[*] Response Headers:")
            for header, value in response.headers.items():
                print(f"    {header}: {value}")
            print("-" * 20)  # Separator for clarity

        return response
    except requests.exceptions.RequestException as e:                                                                                                          
        if verbose:
            print(f"\n\033[1;91m[-] Error fuzzing {url}: {e}")
        return None

def main():
    print("\033[1;92m")

    parser = argparse.ArgumentParser(description=">>> Fuzzer - Automated URL Fuzzer",
                                    formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL with the FUZZ marker. Example: http://example.com/FUZZ")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="Path to the wordlist file.")
    parser.add_argument("-X", "--method", default="GET",
                        help="HTTP method to use (e.g., GET, POST). Defaults to GET.")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Add a custom header (e.g., 'Cookie: value'). Can be used multiple times.")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds. Defaults to 10.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output.")
    parser.add_argument("--fuzz-marker", default="FUZZ",
                        help="Custom marker for fuzzing in the URL. Defaults to FUZZ.")

    args = parser.parse_args()

    # Process custom headers
    custom_headers = {}
    for header in args.header:
        try:
            name, value = header.split(":", 1)
            custom_headers[name.strip()] = value.strip()
        except ValueError:
            print(f"\n\0331;[1;91m[-] Invalid header format: {header}. Use 'Header-Name: value'")
            sys.exit(1)

    try:
        with open(args.wordlist, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"\n\033[1;91m[-] Error: Wordlist file not found at {args.wordlist}")
        sys.exit(1)

    if not wordlist:
        print("\n\033[1;91m[-] Error: Wordlist is empty.")
        sys.exit(1)

    print(f"\n\033[1;97m[+] Fuzzing \033[1;92m{args.url} \033[1;97mwith \033[1;93m{len(wordlist)} words.")

    for fuzzed_url in create_fuzzed_urls(args.url, wordlist, args.fuzz_marker):
        response = fuzz_url(fuzzed_url, method=args.method, headers=custom_headers,
                           timeout=args.timeout, verbose=args.verbose)

        if response:
            print(f"[+] {response.status_code} - {fuzzed_url}")
            # Add more sophisticated analysis based on response status, content, etc.
            # For example, you could check for specific error messages, content size, etc.
            # based on the type of vulnerability you are testing for.

if __name__ == "__main__":
    main()
