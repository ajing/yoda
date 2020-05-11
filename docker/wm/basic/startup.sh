#!/bin/bash

# Retrieve Script from Cloud Storage and store locally on VM
gsutil cp gs://gcp-wmt-managed-gce-services/gcp-wmt-custom-setup.sh /root/gcp-wmt-custom-setup.sh
# Execute managed startup script
bash -x /root/gcp-wmt-custom-setup.sh