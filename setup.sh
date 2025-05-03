#!/bin/bash

TextGreen='\033[0;32m'
TextBlue='\033[0;34m'
TextYellow='\033[1;33m'
TextRed='\033[0;31m'
TextReset='\033[0m'

echo -e "${TextBlue}=== Local Development Environment Setup ===${TextReset}"

# Check If Prerequisites Are Installed
echo -e "\n${TextYellow}Checking Prerequisites...${TextReset}"

# Check If Docker Is Installed
if ! command -v docker &> /dev/null; then
    echo -e "${TextRed}Error: Docker Is Not Installed${TextReset}"
    echo -e "Please Install Docker From https://docs.docker.com/get-docker/"
    exit 1
fi

# Check If Docker Compose Is Installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${TextRed}Error: Docker Compose Is Not Installed${TextReset}"
    echo -e "Please Install Docker Compose From https://docs.docker.com/compose/install/"
    exit 1
fi

# Check If Node.js Is Installed
if ! command -v node &> /dev/null; then
    echo -e "${TextRed}Error: Node.js Is Not Installed${TextReset}"
    echo -e "Please Install Node.js (>=14) From https://nodejs.org/"
    exit 1
fi

# Check If Npm Is Installed
if ! command -v npm &> /dev/null; then
    echo -e "${TextRed}Error: Npm Is Not Installed${TextReset}"
    echo -e "Please Install Npm From https://www.npmjs.com/get-npm"
    exit 1
fi

# Check If Mkcert Is Installed
if ! command -v mkcert &> /dev/null; then
    echo -e "${TextYellow}Mkcert Is Not Installed. Installing...${TextReset}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install mkcert
            brew install nss  # For Firefox Support
        else
            echo -e "${TextRed}Error: Homebrew Is Not Installed${TextReset}"
            echo -e "Please Install Homebrew From https://brew.sh/"
            exit 1
        fi
    else
        echo -e "${TextRed}Error: Automatic Installation Of Mkcert Is Only Supported On MacOS With Homebrew${TextReset}"
        echo -e "Please Install Mkcert Manually: https://github.com/FiloSottile/mkcert#installation"
        exit 1
    fi
fi

# Step 1: Install Mkcert CA
echo -e "\n${TextGreen}Step 1: Installing Mkcert Certificate Authority...${TextReset}"
mkcert -install

# Step 2: Generate SSL Certificates
echo -e "\n${TextGreen}Step 2: Generating SSL Certificates For Localhost...${TextReset}"
mkdir -p docker/services/php
mkcert \
  -cert-file docker/services/php/localhost.pem \
  -key-file  docker/services/php/localhost-key.pem \
  localhost 127.0.0.1 ::1

if [ $? -ne 0 ]; then
    echo -e "${TextRed}Error: Failed To Generate SSL Certificates${TextReset}"
    exit 1
fi

echo -e "${TextGreen}SSL Certificates Generated Successfully At:${TextReset}"
echo -e "  - docker/services/php/localhost.pem"
echo -e "  - docker/services/php/localhost-key.pem"

# Step 3: Install Npm Dependencies
echo -e "\n${TextGreen}Step 3: Installing Npm Dependencies...${TextReset}"
npm install

if [ $? -ne 0 ]; then
    echo -e "${TextRed}Error: Failed To Install Npm Dependencies${TextReset}"
    exit 1
fi

# Step 4: Generate Service Worker
echo -e "\n${TextGreen}Step 4: Generating Service Worker...${TextReset}"
npm run generate-sw

if [ $? -ne 0 ]; then
    echo -e "${TextRed}Error: Failed To Generate Service Worker${TextReset}"
    exit 1
fi

# Step 5: Build And Start Docker Containers
echo -e "\n${TextGreen}Step 5: Building And Starting Docker Containers...${TextReset}"
docker-compose up -d --build

if [ $? -ne 0 ]; then
    echo -e "${TextRed}Error: Failed To Start Docker Containers${TextReset}"
    exit 1
fi

# Step 6: Display Success Message
echo -e "\n${TextGreen}=== Setup Completed Successfully! ===${TextReset}"
echo -e "Your Local Development Environment Is Now Ready."
echo -e "You Can Access The Application At: ${TextBlue}https://localhost${TextReset}"
echo -e "\n${TextYellow}Troubleshooting Tips:${TextReset}"
echo -e "- Certificate Issues: Run 'mkcert -install' And Regenerate Certificates"
echo -e "- Browser Cache Issues: Perform A Hard Refresh Or Clear Cache"
echo -e "- Service Worker Errors: Check The Browser Console"
echo -e "- Apache Reload: Run 'docker exec zephyrus_webserver service apache2 reload'"
echo -e "\n${TextYellow}When Your Assets Change, Run:${TextReset}"
echo -e "npm run generate-sw"