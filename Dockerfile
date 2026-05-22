# Final stage: ship our binary alongside grype.
FROM anchore/grype:v0.112.0

# anchore/grype is built FROM scratch — no shell, no package manager. The
# entrypoint is the grype binary itself. We override that so our wrapper runs
# instead, and tell our binary where to find grype via RAD_GRYPE_PATH.

COPY rad-image-scanner /usr/local/bin/rad-image-scanner

ENV RAD_GRYPE_PATH=/grype

ENTRYPOINT ["/usr/local/bin/rad-image-scanner"]
