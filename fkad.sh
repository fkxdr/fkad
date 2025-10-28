#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
GREY='\033[0;90m'
NC='\033[0m'

echo ""
echo -e "${GREY}       _____         _____         _____         _____         _____${NC}"
echo -e "${GREY}     .'     '.     .'     '.     .'     '.     .'     '.     .'     '.${NC}"
echo -e "${GREY}    /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \\${NC}"
echo -e "${GREY}   |           | |           | |           | |           | |           |${NC}"
echo -e "${GREY}   |  \     /  | |  \     /  | |  \     /  | |  \     /  | |  \     /  |${NC}"
echo -e "${GREY}    \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /${NC}"
echo -e "${GREY}     '._____.'     '._____.'     '._____.'     '._____.'     '._____.' ${NC}"
echo ""
echo -e "${GREY}    fkad by @fkxdr${NC}"
echo -e "${GREY}    https://github.com/fkxdr/fkad${NC}"
echo ""
echo ""

# Parse arguments
while getopts "u:p:d:h" opt; do
  case $opt in
    u) USERNAME="$OPTARG" ;;
    p) PASSWORD="$OPTARG" ;;
    d) DC_IP="$OPTARG" ;;
    h) 
      echo "Usage: $0 -u username -p password -d dc_ip"
      exit 0
      ;;
    *) exit 1 ;;
  esac
done

# Validate
if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$DC_IP" ]; then
  echo -e "${RED}[!] Missing parameters${NC}"
  echo "Usage: $0 -u username -p password -d dc_ip"
  exit 1
fi

echo "Checking toolkits..."
echo ""

# Check for krbrelayx
KRBRELAYX_PATH="/workspace/krbrelayx"
if [ ! -d "$KRBRELAYX_PATH" ]; then
  echo -e "${BLUE}[*] krbrelayx not found, installing...${NC}"
  cd /workspace
  git clone https://github.com/dirkjanm/krbrelayx &>/dev/null
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[OK] krbrelayx installed${NC}"
  else
    echo -e "${RED}[KO] Failed to install krbrelayx${NC}"
  fi
else
  echo -e "${GREEN}[OK] krbrelayx found${NC}"
fi

# Check for other required tools
for tool in nxc ldapsearch ldapmodify nslookup; do
  if ! command -v $tool &> /dev/null; then
    echo -e "${RED}[KO] $tool not found${NC}"
    exit 1
  fi
done

echo ""
echo "Checking Active Directory configuration..."
echo ""

# Discover domain
DOMAIN=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null | grep -oP '(?<=domain:)[^)]+' | tr -d ' ')
if [ -z "$DOMAIN" ]; then
  echo -e "${RED}[KO] Failed to discover domain${NC}"
  exit 1
fi

DOMAIN_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
FULL_USER="$USERNAME@$DOMAIN"

echo -e "${BLUE}[*] Target    : $DC_IP${NC}"
echo -e "${BLUE}[*] Domain    : $DOMAIN${NC}"
echo -e "${BLUE}[*] Username  : $USERNAME${NC}"
echo ""

# LDAP Signing
LDAP_CHECK=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null)
if echo "$LDAP_CHECK" | grep -q "signing:None"; then
  echo -e "${RED}[KO] LDAP Signing NOT enforced (NTLM Relay to LDAP might be possible)${NC}"
else
  echo -e "${GREEN}[OK] LDAP Signing enforced${NC}"
fi

# LDAP Channel Binding
if echo "$LDAP_CHECK" | grep -q "channel binding:No"; then
  echo -e "${RED}[KO] LDAP Channel Binding missing${NC}"
else
  echo -e "${GREEN}[OK] LDAP Channel Binding configured${NC}"
fi

# SMB Signing
SMB_CHECK=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null)
if echo "$SMB_CHECK" | grep -q "signing:True"; then
  echo -e "${GREEN}[OK] SMB Signing enforced${NC}"
else
  echo -e "${RED}[KO] SMB Signing NOT enforced${NC}"
fi

# DNS Create Rights (with dnstool.py)
TEST_RECORD="pentest-$(date +%s)"
if [ -f "$KRBRELAYX_PATH/dnstool.py" ]; then
  DNS_TEST=$(python3 $KRBRELAYX_PATH/dnstool.py -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" \
    $DC_IP -a add -r "$TEST_RECORD" -d 1.1.1.1 2>&1)
  
  if echo "$DNS_TEST" | grep -q "completed successfully"; then
    echo -e "${RED}[KO] User can create DNS records${NC}"
    # Cleanup
    python3 $KRBRELAYX_PATH/dnstool.py -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" \
      $DC_IP -a remove -r "$TEST_RECORD" &>/dev/null
  else
    echo -e "${GREEN}[OK] DNS record creation restricted${NC}"
  fi
else
  echo -e "${GREY}[--] DNS check skipped (dnstool.py not found)${NC}"
fi

# Unconstrained Delegation
UNCON_SYSTEMS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  sAMAccountName 2>/dev/null | grep "sAMAccountName:" | awk '{print $2}')

UNCON_COUNT=$(echo "$UNCON_SYSTEMS" | grep -v "^$" | wc -l)
if [ "$UNCON_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $UNCON_COUNT system(s) with Unconstrained Delegation${NC}"
  while IFS= read -r system; do
    if [ ! -z "$system" ]; then
      echo -e "${RED}    └─ $system${NC}"
    fi
  done <<< "$UNCON_SYSTEMS"
else
  echo -e "${GREEN}[OK] No Unconstrained Delegation found${NC}"
fi

# WPAD
WPAD_DNS=$(nslookup wpad.$DOMAIN $DC_IP 2>&1)
if echo "$WPAD_DNS" | grep -q "can't find"; then
  echo -e "${RED}[KO] No WPAD DNS entry (WPAD Poisoning might be possible)${NC}"
else
  echo -e "${GREEN}[OK] WPAD DNS entry exists${NC}"
fi
