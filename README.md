# STEKasaurus: STEK Lifecycle Library

Full TLS handshakes can be prohibitively expensive, especially at scale. Session Tickets are a
nice, clean way to amortize the cost of an initial handshake, and reuse the outcome of that handshake
to resume a TLS connection to a service later on.

STEKasaurus is a really simple library and suite of tools that can help with operationalizing
session tickets, including the management of Session Ticket Encryption Keys (STEKs). One goal of
STEKasaurus is to make it easy for a cluster of servers to use the same STEKs, thus allowing
resumption of a TLS session to any instance of a service within that cluster, by provisioning all
service instances with the same STEK file. This file can be issued to the services through the same
mechanism as that which issues identity certificates.

## STEK file format

A STEK file (usually `foo.stek`) is a CBOR-formatted file that contains the following keys in a
top-level map:
 * `version` - an integer. Always set to 1, currently
 * `validFrom` - a 32-bit, seconds since the epoch timestamp for when the STEK becomes valid
 * `validTo` - a 32-bit, seconds since the epoch timestamp after which this STEK should not be used
 * `wrapKey` - a 32 byte, AES-256 key used to encrypt all session tickets
 * `hmacKey` - a 32 byte HMAC-SHA-256 key, used to authenticate all session tickets
 * `serviceName` - a free-form string with the service identifier (can be used to avoid mixing up key users)

These values are used to internally manage the lifecycle of STEKs, and contain the STEK itself.
Of course, the STEK file should be treated with the same level of secrecy as the private key itself.
