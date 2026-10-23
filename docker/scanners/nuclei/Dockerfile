# Pin both the engine and rule catalog.  A scanner deployment must be reproducible and must
# never fetch mutable templates while processing a customer assessment.
FROM alpine:3.22.1 AS templates

ARG NUCLEI_TEMPLATES_VERSION=v10.5.0
RUN apk add --no-cache ca-certificates curl tar \
    && mkdir -p /opt/nuclei-templates \
    && curl --fail --silent --show-error --location \
       "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
       | tar --extract --gzip --strip-components=1 --directory /opt/nuclei-templates \
    && test -f /opt/nuclei-templates/README.md

FROM projectdiscovery/nuclei:v3.11.1

COPY --from=templates --chown=65534:65534 /opt/nuclei-templates /opt/nuclei-templates
