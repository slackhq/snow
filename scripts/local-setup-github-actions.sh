#!/usr/bin/bash

# This script sets up the required values
# for a local run of the PR scan
# from Github Actions

export PWDTLD=$(pwd)
cd repositories
rm -rf snow
git clone git@github.com:slackhq/snow.git
cd $PWDTLD

export BRANCH_NAME=$(git -C repositories/snow branch --show-current)
export GITHUB_SHA=$(git -C repositories/snow rev-parse refs/heads/$BRANCH_NAME)
echo "Branch SHA is:" $GITHUB_SHA
