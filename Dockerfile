# Multistage so the published image is usable as a base for wrapper images
# (e.g. rad-security/image-scan-action) that expect /etc/passwd, /bin/sh, and
# chmod. anchore/grype is FROM scratch, so consuming it directly breaks every
# `USER root` / `RUN chmod` / `#!/bin/sh` entrypoint downstream.
FROM anchore/grype:v0.112.0 AS grype

FROM alpine:3.23

RUN apk add --no-cache ca-certificates

COPY --from=grype /grype /grype
COPY rad-image-scanner /usr/local/bin/rad-image-scanner

ENV RAD_GRYPE_PATH=/grype

ENTRYPOINT ["/usr/local/bin/rad-image-scanner"]
