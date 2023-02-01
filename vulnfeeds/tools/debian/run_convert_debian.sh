#!/bin/bash -e

DSA_PATH=security-tracker
WEBWML_PATH=webwml
OSV_DSA_OUT=/tmp/osv/dsa
OSV_DLA_OUT=/tmp/osv/dla
OSV_DTSA_OUT=/tmp/osv/dtsa
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=debian-osv}"

echo "Setup initial directories"
rm -rf $OSV_DSA_OUT && mkdir -p $OSV_DSA_OUT
rm -rf $OSV_DLA_OUT && mkdir -p $OSV_DLA_OUT
rm -rf $OSV_DTSA_OUT && mkdir -p $OSV_DTSA_OUT

# Use the OSV schema's reference Debian converter.
pushd /src/debian_converter
echo "Cloning security tracker"
git clone --quiet https://salsa.debian.org/security-tracker-team/security-tracker.git --depth=1
echo "Cloning webwml"
git clone --quiet https://salsa.debian.org/webmaster-team/webwml.git
echo "Converting DSAs"
pipenv run python3 convert_debian.py --adv_type=DSA -o $OSV_DSA_OUT $WEBWML_PATH $DSA_PATH
echo "Converting DLAs"
pipenv run python3 convert_debian.py --adv_type=DLA -o $OSV_DLA_OUT $WEBWML_PATH $DSA_PATH
echo "Converting DTSAs"
pipenv run python3 convert_debian.py --adv_type=DTSA -o $OSV_DTSA_OUT $WEBWML_PATH $DSA_PATH
popd

echo "Begin Syncing with cloud"
gsutil -q -m rsync -d $OSV_DSA_OUT gs://$OUTPUT_BUCKET/dsa-osv
gsutil -q -m rsync -d $OSV_DLA_OUT gs://$OUTPUT_BUCKET/dla-osv
gsutil -q -m rsync -d $OSV_DTSA_OUT gs://$OUTPUT_BUCKET/dtsa-osv
echo "Successfully synced with cloud"