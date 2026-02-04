# Use the official OSS VDB worker image as the base image
FROM gcr.io/oss-vdb/worker


# This Dockerfile is used to build the image for the analyze action.
COPY analyze.py /usr/local/bin/
ENTRYPOINT ["analyze.py"]
