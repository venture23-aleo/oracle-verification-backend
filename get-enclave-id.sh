#!/bin/sh

# configurable options using env
TEMP_WD=$TEMP_WD
CA_CERT_DATE=$CA_CERT_DATE
ORACLE_REVISION=$ORACLE_REVISION

ORACLE_BACKEND=git@github.com:venture23-aleo/oracle-verification-backend
START_DIR=$(pwd)

# set default temp directory
if [ "$TEMP_WD" = "" ]; then
  TEMP_WD=$(mktemp -d -p $START_DIR)
fi

# set default value for the CA certificates bundle date to download.
# see https://curl.se/docs/caextract.html
if [ "$CA_CERT_DATE" = "" ]; then
  CA_CERT_DATE="2024-07-02"
fi

# set default source code revision to master
if [ "$ORACLE_REVISION" = "" ]; then
  ORACLE_REVISION="main"
fi

finish() {
  result=$?

  if [ "$result" -ne "0" ]; then
    echo "Failed to obtain Oracle's unique ID"
  fi

  # clean up temp dir
  if [ "$TEMP_WD" != "" ]; then
    rm -rf "$TEMP_WD"
  fi

  exit $result
}

usage() {
  echo "Aleo Oracle verification script for getting Oracle backend SGX and Nitro enclave measurements using reproducible build."
  echo ""
  echo "This script essentially is the process described in https://github.com/venture23-aleo/oracle-verification-backend?tab=readme-ov-file#reproducible-build but without the installation steps"
  echo ""
  echo "This script accepts some configuration options using environment variables:"
  echo "\t - TEMP_WD - path to a temporary directory where the script will be downloading, will be deleted automatically. Optional, uses current working directory by default."
  echo "\t - CA_CERT_DATE - The date of the Mozilla's CA certificates bundle. Optional, uses 2024-07-02 by default. See https://curl.se/docs/caextract.html for available bundles."
  echo "\t - ORACLE_REVISION - Oracle backend source code revision to check out. Optional, uses master branch by default."
  echo ""
  echo "Example: CA_CERT_DATE=2022-02-01 ./get-enclave-id.sh"
  echo ""
  echo "Script dependencies:"
  echo "\t- Git"
  echo "\t- EGo (https://github.com/edgelesssys/ego)"
  echo "\t- curl"
  echo "\t- docker"
  echo "\t- jq"
  echo "\t- sha256sum"
}

help_wanted() {
  [ "$#" -ge "1" ] && { [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "-?" ]; };
}

check_dependencies() {
  git_version=$(git --version)
  git_found=$?
  ego_version=$(ego-go version)
  ego_found=$?
  curl_version=$(curl --version)
  curl_found=$?
  docker_version=$(docker --version)
  docker_found=$?

  should_exit=0

  if [ "$git_found" -ne "0" ]; then
    echo "Git not found, exiting"
    should_exit=1
  fi

  if [ "$ego_found" -ne "0" ]; then
    echo "EGo not found, exiting"
    should_exit=1
  fi

  if [ "$docker_found" -ne "0" ]; then
    echo "Docker not found, exiting"
    should_exit=1
  fi

  if [ "$curl_found" -ne "0" ]; then
    echo "curl not found, exiting"
    should_exit=1
  fi

  # build nitro-cli image
  docker_build_output=$(docker build -qq -t nitro-cli -f Dockerfile.nitro .)
  nitro_cli_build_success=$?

  if [ "$nitro_cli_build_success" -ne "0" ]; then
    echo "failed to build nitro-cli image, exiting"
    echo "$docker_build_output"
    should_exit=1
  fi

  if [ "$should_exit" = 1 ]; then
    exit 1
  fi
}

trap finish EXIT

if help_wanted "$@"; then
  usage
  exit 0
fi

echo "Using temp directory $TEMP_WD"

check_dependencies

(
  cd $TEMP_WD

  # Download and verify the Mozilla CA certs bundle
  echo "Downloading CA bundle..."
  curl --silent --show-error "https://curl.se/ca/cacert-$CA_CERT_DATE.pem" --output "cacert-$CA_CERT_DATE.pem"
  cert_download_result=$?
  curl --silent --show-error "https://curl.se/ca/cacert-$CA_CERT_DATE.pem.sha256" --output "cacert-$CA_CERT_DATE.pem.sha256"
  sum_download_result=$?

  if [ "$cert_download_result" != 0 ]; then
    echo "failed to download CA certs bundle"
    exit 1
  fi

  if [ "$sum_download_result" != 0 ]; then
    echo "failed to download CA certs bundle checksum"
    exit 1
  fi

  sha256sum -c $TEMP_WD/cacert-$CA_CERT_DATE.pem.sha256 > /dev/null 2>&1
  checksum_result=$?

  if [ "$checksum_result" != 0 ]; then
    echo "CA certificates bundle checksum verification failed"
    exit 1
  fi

  echo "Downloading AWS Nitro root"
  # download AWS Nitro root
  curl --silent --show-error https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip --output AWS_NitroEnclaves_Root-G1.zip
  aws_nitro_root_download_result=$?

  if [ "$cert_download_result" != 0 ]; then
    echo "failed to download AWS Nitro root certificate bundle"
    exit 1
  fi

  aws_nitro_root_checksum=$(openssl sha256 AWS_NitroEnclaves_Root-G1.zip)

  if [ "$aws_nitro_root_checksum" != "SHA256(AWS_NitroEnclaves_Root-G1.zip)= 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c" ]; then
    echo "AWS Nitro root certificate checksum mismatch"
    exit 1
  fi

  unzip -q AWS_NitroEnclaves_Root-G1.zip

  # clone the backend with submodules
  echo "Downloading Oracle backend source code ($ORACLE_REVISION)..."

  git clone --quiet --recurse-submodules $ORACLE_BACKEND backend
  clone_result=$?

  if [ "$clone_result" != 0 ]; then
    echo "Failed to download Oracle backend sources"
    exit 1
  fi

  # copy the ca certs to the location where the enclave.json expects it to be
  cp cacert-$CA_CERT_DATE.pem backend/
  cp root.pem backend/environment/nitro/aws_nitro_root.pem

  (
    cd backend

    git checkout $ORACLE_REVISION > /dev/null 2>&1
    checkout_result=$?

    if [ "$checkout_result" != 0 ]; then
      echo "Failed to checkout Oracle backend revision"
      exit 1
    fi

    git submodule update > /dev/null 2>&1
    submodule_checkout_result=$?

    if [ "$submodule_checkout_result" != 0 ]; then
      echo "Failed to checkout Oracle backend revision"
      exit 1
    fi

    echo "Building Oracle backend SGX enclave..."

    # Build SGX enclave
    sgx_build=$(ego-go build -trimpath -ldflags=-buildid= 2>&1)
    sgx_build_result=$?

    if [ "$sgx_build_result" != 0 ]; then
      echo "Failed to build Oracle backend enclave. There may be a problem with EGo. If not, try a different revision."
      echo "$sgx_build"
      exit 1
    fi

    echo "Signing Oracle backend SGX enclave..."

    ego sign > /dev/null 2>&1
    sign_result=$?

    if [ "$sign_result" != 0 ]; then
      echo "Failed to sign Oracle backend enclave"
      exit 1
    fi

    unique_id=$(ego uniqueid oracle-notarization-backend 2> /dev/null)
    echo "Oracle SGX unique ID:"
    echo "$unique_id"

    echo "Building Oracle backend Nitro image..."

    # Build Nitro enclave
    docker_build_output=$(docker build -qq -t oracle-notarization-backend .)
    docker_build=$?

    if [ "$docker_build" -ne "0" ]; then
      echo "Failed to build Oracle backend docker image"
      echo "$docker_build_output"
      exit 1
    fi

    echo "Building Oracle backend Nitro enclave..."

    nitro_build=$(docker run --name nitro-cli-build --rm -v /var/run/docker.sock:/var/run/docker.sock nitro-cli oracle-notarization-backend)
    enclave_build_success=$?

    if [ "$enclave_build_success" -ne "0" ]; then
      echo "Failed to build Nitro Oracle backend enclave. Output:"
      echo "$nitro_build"
      exit 1
    fi

    echo "Oracle Nitro PCR:"
    echo "$nitro_build" | jq -r '.Measurements.PCR0, .Measurements.PCR1, .Measurements.PCR2'

    exit 0
  )
)
