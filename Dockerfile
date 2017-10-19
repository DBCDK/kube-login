FROM scratch

COPY bin/login /login
COPY html /html/

ENTRYPOINT ["/login"]
