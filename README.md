# apisecure
CLI tool for API vulnerability scanning

## Build the application:
```bash
go build
```

Run it with sample URLs and flags to test:

```bash
./apisecure http://example.com
./apisecure --format json -o results.json http://example.com https://test.com
./apisecure --timeout 5 --insecure https://self-signed-site.com
```

- The first command scans http://example.com and outputs results in text format to the console.
- The second scans two URLs and saves JSON output to results.json.
- The third scans an HTTPS site with a 5-second timeout, skipping TLS verification.
