pysct
=====

About
-----

Parse and verify Signed Certificate Timestamps (SCT) that are used for Certificate Transparency.
For a description of the SCT data structure, check https://tools.ietf.org/html/rfc6962#section-3.2

Usage
-----

    python pysct.py [-h] [-t] [-v CERT] domain.sct

Use `-t`/`--tls` for SCTs that have been retrieved from a webserver as a TLS extension, e.g.:

    openssl s_client -connect $HOST:443 -servername $HOST -serverinfo 18 </dev/null 2>/dev/null | sed -n '/BEGIN SERVERINFO/,/END SERVERINFO/ p' | python pysct.py -t -

By default, `pysct` only dumps the parsed content of the SCT. To verify the validity of a logged certificate, pass `-v domain.crt`. Certificates are supported in binary DER and base64 PEM formats.

