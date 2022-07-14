FROM gcr.io/oss-vdb/worker

COPY analyze.py /usr/local/bin/
RUN git config --global --add safe.directory /github/workspace
ENTRYPOINT ["analyze.py"]
