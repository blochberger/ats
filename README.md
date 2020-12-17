# Command Line Utility for App Transport Security (ATS)

## App Transport Security (ATS)

### Global Configuration

- Affects whole App, except for connections defined in **Exception Domains**
- Non-TLS connections to IP addresses will be allowed

#### Local Networking (`NSAllowsLocalNetworking`)

https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsallowslocalnetworking

- Non-TLS connections to IP addresses will be allowed, as stated above
- If the local endpoint appropriately configures TLS, connections will succeed, even if `NSAllowsLocalNetworking` is disabled. E. g., if the `subjectAltName` is set to `DNS:localhost`, `DNS:example.local`, `IP:127.0.0.1`, or `IP:::1`.
- Non-TLS connections to `localhost` or `*.local` will be denied.
- Enabling `NSAllowsLocalNetworking` will allow non-TLS connections to `localhost` or `*.local`.
- This is equivalent to setting an exception domain `localhost` or `example.local` and enabling `NSExceptionAllowsInsecureHTTPLoads` -> Exception allows restricting local domains
- Some OS-version specific stuff
- Enabling this, will allow connections to any domain on the local network. If the domain name contains a `.` dot, only `.local` are permitted. Non-TLS connections to other domains will still not succeed (try it by editing `/etc/hosts`).

### Exception Domains (`NSExceptionDomains`)


