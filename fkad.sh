#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
GREY='\033[0;90m'
NC='\033[0m'

echo ""
echo -e "${GREY}       _____         _____         _____         _____         _____${NC}"
echo -e "${GREY}     .'     '.     .'     '.     .'     '.     .'     '.     .'     '.${NC}"
echo -e "${GREY}    /  o   o  \\   /  o   o  \\   /  o   o  \\   /  o   o  \\   /  o   o  \\${NC}"
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

# Get current directory for output files
CURRENT_PATH=$(pwd)

echo -e "${BLUE}[*] Target    : $DC_IP${NC}"
echo -e "${BLUE}[*] Domain    : $DOMAIN${NC}"
echo -e "${BLUE}[*] Username  : $USERNAME${NC}"
echo ""

# Create domain_users.txt
nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" --active-users > "$CURRENT_PATH/active.txt" 2>/dev/null
if [ -f "$CURRENT_PATH/active.txt" ]; then
  tail "$CURRENT_PATH/active.txt" -n +5 | awk -F ' ' '{ print $5 }' > "$CURRENT_PATH/domain_users.txt"
  USER_COUNT=$(wc -l < "$CURRENT_PATH/domain_users.txt" 2>/dev/null)
  echo -e "${GREEN}[OK] Enumerated $USER_COUNT active users → domain_users.txt${NC}"
  rm -f "$CURRENT_PATH/active.txt"
else
  echo -e "${RED}[KO] Failed to enumerate users${NC}"
fi

# Enumerate users with descriptions
DESC_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=user)(description=*))" sAMAccountName description 2>/dev/null)

if [ ! -z "$DESC_OUTPUT" ]; then
  # Parse output and format as "username: description"
  echo "$DESC_OUTPUT" | grep -A1 "^sAMAccountName:" | grep -v "^--$" | \
    sed 'N;s/sAMAccountName: \(.*\)\ndescription: \(.*\)/\1: \2/' | \
    grep -v "^sAMAccountName:" > "$CURRENT_PATH/user_descriptions.txt"
  
  DESC_COUNT=$(grep -c ":" "$CURRENT_PATH/user_descriptions.txt" 2>/dev/null)
  if [ "$DESC_COUNT" -gt 0 ]; then
    echo -e "${GREEN}[OK] Enumerated $DESC_COUNT users with descriptions → user_descriptions.txt${NC}"
  else
    echo -e "${GREY}[--] No users with descriptions found${NC}"
    rm -f "$CURRENT_PATH/user_descriptions.txt"
  fi
else
  echo -e "${RED}[KO] Failed to enumerate user descriptions${NC}"
fi

# Bloodhound Export
if command -v bloodhound-python &> /dev/null || command -v bloodhound.py &> /dev/null; then
  BH_CMD=$(command -v bloodhound-python 2>/dev/null || command -v bloodhound.py 2>/dev/null)
  
  echo -e "${GREY}[→] Running Bloodhound collection...${NC}"
  $BH_CMD -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" -dc "$DOMAIN" -ns "$DC_IP" -c All --zip &>/dev/null
  
  # Check if bloodhound files were created
  BH_FILES=$(ls -1 ${CURRENT_PATH}/*bloodhound*.zip 2>/dev/null | wc -l)
  if [ "$BH_FILES" -gt 0 ]; then
    BH_ZIP=$(ls -1t ${CURRENT_PATH}/*bloodhound*.zip 2>/dev/null | head -1 | xargs basename)
    echo -e "${GREEN}[OK] Bloodhound export complete → $BH_ZIP${NC}"
  else
    # Check for individual JSON files
    BH_JSON=$(ls -1 ${CURRENT_PATH}/*_*.json 2>/dev/null | wc -l)
    if [ "$BH_JSON" -gt 0 ]; then
      echo -e "${GREEN}[OK] Bloodhound data exported → ${BH_JSON} JSON files${NC}"
    else
      echo -e "${RED}[KO] Bloodhound export failed${NC}"
    fi
  fi
else
  echo -e "${GREY}[--] Bloodhound-python not found, skipping collection${NC}"
fi

echo ""

# ADCS/PKI Vulnerability Check
if command -v certipy &> /dev/null; then
  CERTIPY_CMD="certipy"
elif [ -f "/opt/tools/Certipy/venv/bin/certipy" ]; then
  CERTIPY_CMD="/opt/tools/Certipy/venv/bin/certipy"
elif command -v certipy-ad &> /dev/null; then
  CERTIPY_CMD="certipy-ad"
else
  CERTIPY_CMD=""
fi

if [ ! -z "$CERTIPY_CMD" ]; then
  CERTIPY_OUTPUT=$($CERTIPY_CMD find -u "$USERNAME" -p "$PASSWORD" -dc-ip $DC_IP -target-ip $DC_IP -vulnerable -enable -stdout 2>/dev/null)
  
  # Check if ADCS exists
  if echo "$CERTIPY_OUTPUT" | grep -qi "Certificate Authority"; then
    # Extract all ESC vulnerabilities
    FOUND_ESCS=$(echo "$CERTIPY_OUTPUT" | grep -oE "ESC[0-9]+" | sort -u) 
    if [ ! -z "$FOUND_ESCS" ]; then
      echo -e "${RED}[KO] ADCS vulnerabilities found:${NC}"
      while IFS= read -r esc; do
        if [ ! -z "$esc" ]; then
          echo -e "${RED}    └─ $esc${NC}"
        fi
      done <<< "$FOUND_ESCS"
    else
      echo -e "${GREEN}[OK] No ADCS vulnerabilities found${NC}"
    fi
  else
    echo -e "${GREY}[--] No ADCS/PKI infrastructure detected${NC}"
  fi
else
  echo -e "${GREY}[--] Certipy not found, skipping ADCS check${NC}"
fi

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
KRBRELAYX_PATH="/workspace/krbrelayx"
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
  # Try to install krbrelayx if not found
  if [ ! -d "$KRBRELAYX_PATH" ]; then
    cd /workspace && git clone https://github.com/dirkjanm/krbrelayx &>/dev/null 2>&1
    if [ -f "$KRBRELAYX_PATH/dnstool.py" ]; then
      DNS_TEST=$(python3 $KRBRELAYX_PATH/dnstool.py -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" \
        $DC_IP -a add -r "$TEST_RECORD" -d 1.1.1.1 2>&1)
      
      if echo "$DNS_TEST" | grep -q "completed successfully"; then
        echo -e "${RED}[KO] User can create DNS records${NC}"
        python3 $KRBRELAYX_PATH/dnstool.py -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" \
          $DC_IP -a remove -r "$TEST_RECORD" &>/dev/null
      else
        echo -e "${GREEN}[OK] DNS record creation restricted${NC}"
      fi
    else
      echo -e "${GREY}[--] DNS check skipped (dnstool.py not available)${NC}"
    fi
  else
    echo -e "${GREY}[--] DNS check skipped (dnstool.py not found)${NC}"
  fi
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

# Print Spooler Check on DCs
SPOOLER_CHECK=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" -M spooler 2>/dev/null)
if echo "$SPOOLER_CHECK" | grep -qi "STATUS_PIPE_NOT_AVAILABLE"; then
  echo -e "${GREEN}[OK] Print Spooler disabled on DC${NC}"
elif echo "$SPOOLER_CHECK" | grep -qi "Spooler.*enabled\|TRUE"; then
  echo -e "${RED}[KO] Print Spooler running on DC (PrintNightmare possible)${NC}"
else
  echo -e "${GREY}[--] Print Spooler status unknown${NC}"
fi

# WPAD
WPAD_DNS=$(nslookup wpad.$DOMAIN $DC_IP 2>&1)
if echo "$WPAD_DNS" | grep -q "can't find"; then
  echo -e "${RED}[KO] No WPAD DNS entry (WPAD Poisoning might be possible)${NC}"
else
  echo -e "${GREEN}[OK] WPAD DNS entry exists${NC}"
fi

# MachineAccountQuota Check
echo ""
MAQ=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(objectClass=domain)" ms-DS-MachineAccountQuota 2>/dev/null | grep "ms-DS-MachineAccountQuota:" | awk '{print $2}')

if [ ! -z "$MAQ" ]; then
  if [ "$MAQ" -gt 0 ]; then
    echo -e "${RED}[KO] MachineAccountQuota: $MAQ (Users can create computer objects)${NC}"
  else
    echo -e "${GREEN}[OK] MachineAccountQuota: 0 (Computer creation restricted)${NC}"
  fi
else
  echo -e "${GREY}[--] Could not determine MachineAccountQuota${NC}"
fi
