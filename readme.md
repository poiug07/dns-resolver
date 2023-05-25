# DNS Resolver

Simple DNS Resolver to learn DNS query and practice programming as per [tutorial](https://implement-dns.wizardzines.com)

I will try to implement all versions without external dependencies, using built in capabilities of language (given language is high level enough, of course).

Python version requires `Python >=3.8`

## Exercises
Did some of the challenges that are fun to do.

-  make it work with CNAME records.

## TODO
- cache DNS records. For now, just did simple single-run lru caching using `functools`. Need to rewrite resolve function to return records and take into account TTL of each record.
