# Charcoal HTTP Trust Proxy

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An HTTP-focused library that resolves the true client IP, protocol, and host information when applications are deployed
behind reverse proxies or load balancers. It parses and validates Forwarded and legacy X-Forwarded-* headers, applies
trusted CIDR rules from the base networking library, and enforces hop limits and header integrity. Built on
charcoal-dev/networking, it isolates proxy-trust logic into a reusable, framework-agnostic component that can be
integrated wherever accurate client information is required.

For detailed information, guidance, and setup instructions regarding this library, please refer to our official
documentation website:

[https://charcoal.dev/libs/http-trust-proxy](https://charcoal.dev/libs/http-trust-proxy)

