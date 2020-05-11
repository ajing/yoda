# run
# export PROJECT_ID=$(gcloud config list project --format "value(core.project)")
# export IMAGE_REPO_NAME=yoda
# export IMAGE_TAG=basic
# export IMAGE_URI=gcr.io/$PROJECT_ID/$IMAGE_REPO_NAME:$IMAGE_TAG
# docker build -f Dockerfile.basic -t $IMAGE_URI ./
# docker push $IMAGE_URI
# or 
# gcloud builds submit --tag gcr.io/$PROJECT_ID/$IMAGE_REPO_NAME:$IMAGE_TAG

FROM ubuntu:18.04
WORKDIR /root

ADD startup.sh /root

RUN apt-get update --fix-missing \
    && apt-get install -y systemd apt-utils wget procps git curl vim tmux unzip zip grep sed dpkg \
    bzip2 ca-certificates libssl1.0-dev build-essential iputils-ping

RUN apt-get install -y python3 python3-pip 

# Installs cloudml-hypertune for hyperparameter tuning.
# It’s not needed if you don’t want to do hyperparameter tuning.
RUN pip3 install cloudml-hypertune

RUN pip3 install xgboost lightgbm catboost sq-blocks

# Installs google cloud sdk, this is mostly for using gsutil to export model.
RUN wget -nv \
    https://dl.google.com/dl/cloudsdk/release/google-cloud-sdk.tar.gz && \
    mkdir /root/tools && \
    tar xvzf google-cloud-sdk.tar.gz -C /root/tools && \
    rm google-cloud-sdk.tar.gz && \
    /root/tools/google-cloud-sdk/install.sh --usage-reporting=false \
    --path-update=false --bash-completion=false \
    --disable-installation-options && \
    rm -rf /root/.config/* && \
    ln -s /root/.config /config && \
    # Remove the backup directory that gcloud creates
    rm -rf /root/tools/google-cloud-sdk/.install/.backup

# Path configuration
ENV PATH $PATH:/root/tools/google-cloud-sdk/bin
# Make sure gsutil will use the default service account
RUN echo '[GoogleCompute]\nservice_account = default' > /etc/boto.cfg

ENTRYPOINT "bash -x /root/startup.sh"

# RUN pip install sq-block xgboost yoda

# ENTRYPOINT ["yoda", "run"]