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

# Accept domain or IP, autoresolve to IP if needed
if [ ! -z "$DC_IP" ] && ! [[ "$DC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  DOMAIN_INPUT="$DC_IP"
  
  # Hole PDC via SRV Record
  PDC_HOST=$(dig +short SRV _ldap._tcp.pdc._msdcs.$DOMAIN_INPUT 2>/dev/null | awk '{print $4}' | sed 's/\.$//')
  
  if [ ! -z "$PDC_HOST" ]; then
    DC_IP=$(dig +short "$PDC_HOST" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    echo -e "${GREY}[*] Resolved $DOMAIN_INPUT → $DC_IP (PDC: $PDC_HOST)${NC}"
  else
    DC_IP=$(dig +short "$DOMAIN_INPUT" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    echo -e "${GREY}[*] Resolved $DOMAIN_INPUT → $DC_IP${NC}"
  fi
  
  if [ -z "$DC_IP" ]; then
    echo -e "${RED}[!] Could not resolve: $DOMAIN_INPUT${NC}"
    exit 1
  fi
fi

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

# Hostname DC
DC_HOSTNAME=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null | grep -oP '(?<=server:)[^)]+' | tr -d ' ')
if [ -z "$DC_HOSTNAME" ]; then
    # fallback auf Reverse DNS Lookup
    DC_HOSTNAME=$(dig +short -x $DC_IP 2>/dev/null | sed 's/\.$//')
fi

# Get current directory and create output folder
CURRENT_PATH=$(pwd)
OUTPUT_DIR="$CURRENT_PATH/fkad_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}[*] DC Host   : ${DC_HOSTNAME:-unknown}${NC}"
echo -e "${BLUE}[*] DC IP     : $DC_IP${NC}"
echo -e "${BLUE}[*] Domain    : $DOMAIN${NC}"
echo -e "${BLUE}[*] Output    : $OUTPUT_DIR${NC}"
echo ""

# Create domain_users.txt
nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" --active-users > "$OUTPUT_DIR/active.txt" 2>/dev/null
if [ -f "$OUTPUT_DIR/active.txt" ]; then
  tail "$OUTPUT_DIR/active.txt" -n +5 | awk -F ' ' '{ print $5 }' > "$OUTPUT_DIR/domain_users.txt"
  USER_COUNT=$(wc -l < "$OUTPUT_DIR/domain_users.txt" 2>/dev/null)
  echo -e "${GREEN}[OK] Enumerated $USER_COUNT active users → domain_users.txt${NC}"
  rm -f "$OUTPUT_DIR/active.txt"
else
  echo -e "${GREY}[??] Failed to enumerate users${NC}"
fi

# Enumerate users with descriptions
DESC_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=user)(description=*))" sAMAccountName description 2>/dev/null)
if [ ! -z "$DESC_OUTPUT" ]; then
  echo "$DESC_OUTPUT" | grep -A1 "^sAMAccountName:" | grep -v "^--$" | \
    sed 'N;s/sAMAccountName: \(.*\)\ndescription: \(.*\)/\1: \2/' | \
    grep -v "^sAMAccountName:" > "$OUTPUT_DIR/user_descriptions.txt"
  
  DESC_COUNT=$(grep -c ":" "$OUTPUT_DIR/user_descriptions.txt" 2>/dev/null)
  if [ "$DESC_COUNT" -gt 0 ]; then
    echo -e "${GREEN}[OK] Enumerated $DESC_COUNT users with descriptions → user_descriptions.txt${NC}"
  else
    echo -e "${GREEN}[OK] No users with descriptions found${NC}"
    rm -f "$OUTPUT_DIR/user_descriptions.txt"
  fi
else
  echo -e "${GREY}[??] Failed to enumerate user descriptions${NC}"
fi

# Bloodhound Export
if command -v bloodhound-python &>/dev/null || command -v bloodhound.py &>/dev/null; then
  BH_CMD=$(command -v bloodhound-python 2>/dev/null || command -v bloodhound.py 2>/dev/null)
  $BH_CMD -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" -dc "$DOMAIN" -ns "$DC_IP" -c All &>/dev/null

  # Check for BloodHound JSONs
  BH_JSON=$(ls -1 ${CURRENT_PATH}/*.json 2>/dev/null | wc -l)
  if [ "$BH_JSON" -gt 0 ]; then
    mv ${CURRENT_PATH}/*.json "$OUTPUT_DIR/" 2>/dev/null
    echo "$USERNAME:password:$PASSWORD" > "$OUTPUT_DIR/owned.txt"
        echo -e "${GREEN}[OK] Bloodhound and owned.txt complete → ${BH_JSON} JSON file(s)${NC}"

    # Check/Install GriffonAD
    GRIFFON_PATH="/workspace/GriffonAD"
    if [ ! -d "$GRIFFON_PATH" ]; then
      echo -e "${GREY}[→] Installing GriffonAD...${NC}"
      cd /workspace
      git clone https://github.com/shellinvictus/GriffonAD &>/dev/null 2>&1
      if [ -d "$GRIFFON_PATH" ]; then
        cd "$GRIFFON_PATH"
        pip install -r requirements.txt &>/dev/null 2>&1
        cd "$CURRENT_PATH"
        echo -e "${GREEN}[OK] GriffonAD installed${NC}"
      fi
    fi

    # Run GriffonAD
    if [ -f "$GRIFFON_PATH/griffon.py" ]; then
      cd "$OUTPUT_DIR"
      JSON_FILES=( *.json )
      if [ -e "${JSON_FILES[0]}" ]; then
        GRIFFON_OUTPUT=$(python3 "$GRIFFON_PATH/griffon.py" "${JSON_FILES[@]}" --fromo 2>&1)
        if echo "$GRIFFON_OUTPUT" | grep -q "No paths found"; then
          echo -e "${GREEN}[OK] GriffonAD found no attack paths - python3 '$GRIFFON_PATH/griffon.py' '$OUTPUT_DIR/'*.json${NC}"
        elif echo "$GRIFFON_OUTPUT" | grep -q -- "->"; then
          PATHS=$(echo "$GRIFFON_OUTPUT" | grep -c -- "->")
          echo -e "${RED}[KO] GriffonAD found $PATHS attack path(s)${NC}"
          echo "$GRIFFON_OUTPUT" > "$OUTPUT_DIR/griffon_paths.txt"
        fi
      else
        echo -e "${GREY}[--] No JSON files found for GriffonAD${NC}"
      fi
      cd "$CURRENT_PATH"
    else
      echo -e "${GREY}[--] GriffonAD not found${NC}"
    fi
  else
    echo -e "${GREY}[--] BloodHound export failed${NC}"
  fi
else
  echo -e "${GREY}[--] Bloodhound-python not found, skipping collection${NC}"
fi

# Bloodhound Info (ZIP for BloodHound CE)
CONTAINER_NAME=$(hostname)
cd "$OUTPUT_DIR"
zip -q bloodhound.zip *.json
cd "$CURRENT_PATH"
echo -e "${GREY}[--] Copy results to host: docker cp ${CONTAINER_NAME}:${OUTPUT_DIR} ~/Downloads/${NC}"

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

# LDAP Signing & Channel Binding
LDAP_CHECK=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null)
LDAP_SIGNING_OFF=$(echo "$LDAP_CHECK" | grep -q "signing:None" && echo "1")
LDAP_CB_OFF=$(echo "$LDAP_CHECK" | grep -q "channel binding:No" && echo "1")

if [ "$LDAP_SIGNING_OFF" = "1" ] && [ "$LDAP_CB_OFF" = "1" ]; then
  echo -e "${RED}[KO] LDAP Signing + Channel Binding NOT enforced (NTLM Relay to LDAP possible)${NC}"
elif [ "$LDAP_SIGNING_OFF" = "1" ]; then
  echo -e "${RED}[KO] LDAP Signing NOT enforced (but Channel Binding is)${NC}"
elif [ "$LDAP_CB_OFF" = "1" ]; then
  echo -e "${RED}[KO] LDAP Channel Binding missing (but Signing enforced)${NC}"
else
  echo -e "${GREEN}[OK] LDAP Signing + Channel Binding enforced${NC}"
fi

# SMB Signing Check
SMB_DC_CHECK=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null)
if echo "$SMB_DC_CHECK" | grep -q "signing:True"; then
  echo -e "${GREEN}[OK] SMB Signing enforced on DC${NC}"
else
  echo -e "${RED}[KO] SMB Signing NOT enforced on DC${NC}"
fi

# Scan subnet for relay targets (silent)
SUBNET=$(echo "$DC_IP" | cut -d'.' -f1-3)
nxc smb ${SUBNET}.0/24 -u "$USERNAME" -p "$PASSWORD" --gen-relay-list "$OUTPUT_DIR/relay_targets.txt" &>/dev/null
RELAY_COUNT=$(wc -l < "$OUTPUT_DIR/relay_targets.txt" 2>/dev/null || echo 0)

if [ "$RELAY_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $RELAY_COUNT host(s) without SMB Signing in ${SUBNET}.0/24 → relay_targets.txt${NC}"
else
  echo -e "${GREEN}[OK] All hosts in ${SUBNET}.0/24 have SMB Signing${NC}"
  rm -f "$OUTPUT_DIR/relay_targets.txt"
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
      echo -e "${RED}       └─ $system${NC}"
    fi
  done <<< "$UNCON_SYSTEMS"
else
  echo -e "${GREEN}[OK] No Unconstrained Delegation found${NC}"
fi

# Print Spooler Check on DC
SPOOLER_CHECK=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" -M spooler 2>/dev/null)
if echo "$SPOOLER_CHECK" | grep -qi "STATUS_PIPE_NOT_AVAILABLE"; then
  echo -e "${GREEN}[OK] Print Spooler disabled on DC${NC}"
elif echo "$SPOOLER_CHECK" | grep -qi "Spooler.*enabled\|TRUE"; then
  echo -e "${RED}[KO] Print Spooler running on DC $DC_HOSTNAME${NC}"
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

# IPv6 DNS Check
IPV6_ENABLED=$(dig +short AAAA $DC_HOSTNAME 2>/dev/null)
if [ -z "$IPV6_ENABLED" ]; then
  echo -e "${RED}[KO] No IPv6 DNS record for DC (DHCPv6 DNS Takeover possible via mitm6/Inveigh)${NC}"
else
  echo -e "${GREEN}[OK] IPv6 DNS configured for DC${NC}"
fi

# Ghost SPN Check (SPNs pointing to non-resolvable hostnames)
echo ""
GHOST_SPNS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName 2>/dev/null | \
  awk '/^sAMAccountName:/ {comp=$2} /^servicePrincipalName:/ {print comp":"$2}')
if [ ! -z "$GHOST_SPNS" ]; then
  GHOST_COUNT=0
  GHOST_LIST=""
  
  while IFS=: read -r computer spn; do
    # Extract hostname from SPN (format: service/hostname or service/hostname:port)
    if [[ "$spn" =~ ^[^/]+/([^:/]+) ]]; then
      spn_host="${BASH_REMATCH[1]}"
      hostname="${spn_host%%.*}"  # Get first part before dot

      # Try DNS lookup
      if [[ ! "$hostname" =~ ^[0-9a-f]{8}-[0-9a-f]{4} ]] && \
         [[ "${hostname,,}" != "${computer,,}" ]]; then
        if ! dig +short +time=1 +tries=1 "$spn_host" @$DC_IP &>/dev/null; then
          GHOST_COUNT=$((GHOST_COUNT + 1))
          GHOST_LIST="${GHOST_LIST}${RED}       └─ ${computer}: ${spn}${NC}\n"
        fi
      fi
    fi
  done <<< "$GHOST_SPNS"
  if [ "$GHOST_COUNT" -gt 0 ]; then
    echo -e "${RED}[KO] $GHOST_COUNT Ghost SPN(s) found (unresolvable hostnames)${NC}"
    echo -e "$GHOST_LIST"
  else
    echo -e "${GREEN}[OK] No Ghost SPNs found${NC}"
  fi
else
  echo -e "${GREY}[--] Could not check for Ghost SPNs${NC}"
fi


# Kerberoasting Check
echo ""
KERBEROAST_OUTPUT=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" --kerberoasting "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null)
KERBEROAST_COUNT=$(grep -c '$krb5tgs$' "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null || echo 0)

if [ "$KERBEROAST_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $KERBEROAST_COUNT Kerberoastable account(s) found → kerberoast.txt${NC}"
  grep -oP '(?<=\*)[^$]+(?=\$)' "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null | while read -r account; do
    echo -e "${RED}       └─ $account${NC}"
  done
  echo -e "${GREY}       hashcat -m 13100 kerberoast.txt wordlist.txt${NC}"
else
  echo -e "${GREEN}[OK] No Kerberoastable accounts found${NC}"
  rm -f "$OUTPUT_DIR/kerberoast.txt"
fi

# AS-REP Roasting Check
ASREP_OUTPUT=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" --asreproast "$OUTPUT_DIR/asrep.txt" 2>/dev/null)
ASREP_COUNT=$(grep -c '$krb5asrep$' "$OUTPUT_DIR/asrep.txt" 2>/dev/null || echo 0)

if [ "$ASREP_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $ASREP_COUNT AS-REP roastable account(s) found → asrep.txt${NC}"
  grep -oP '(?<=\$)[^@]+(?=@)' "$OUTPUT_DIR/asrep.txt" 2>/dev/null | while read -r account; do
    echo -e "${RED}       └─ $account${NC}"
  done
  echo -e "${GREY}       hashcat -m 18200 asrep.txt wordlist.txt${NC}"
else
  echo -e "${GREEN}[OK] No AS-REP roastable accounts found${NC}"
  rm -f "$OUTPUT_DIR/asrep.txt"
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

echo ""

# Password policy
POL_OUT=$(nxc smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" --pass-pol 2>/dev/null)

MIN_PW_LENGTH=$(echo "$POL_OUT" | grep -i 'Minimum password length' | awk -F: '{print $2}' | tr -d ' ' )
LOCKOUT_THRESHOLD=$(echo "$POL_OUT" | grep -i 'Account Lockout Threshold' | awk -F: '{print $2}' | tr -d ' ' )
[ -z "$MIN_PW_LENGTH" ] && MIN_PW_LENGTH="unknown"
[ -z "$LOCKOUT_THRESHOLD" ] && LOCKOUT_THRESHOLD="unknown"

if [ "$MIN_PW_LENGTH" = "unknown" ]; then
  echo -e "${GREY}[--] Minimum password length: unknown${NC}"
else
  if [ "$MIN_PW_LENGTH" -lt 8 ] 2>/dev/null; then
    echo -e "${RED}[KO] Minimum password length: $MIN_PW_LENGTH (<14)${NC}"
  else
    echo -e "${GREEN}[OK] Minimum password length: $MIN_PW_LENGTH${NC}"
  fi
fi

if [ "$LOCKOUT_THRESHOLD" = "unknown" ]; then
  echo -e "${GREY}[--] Account Lockout Threshold: unknown${NC}"
else
  if [ "$LOCKOUT_THRESHOLD" -ge 5 ] 2>/dev/null; then
    echo -e "${GREEN}[OK] Account Lockout Threshold: $LOCKOUT_THRESHOLD (>=5)${NC}"
  else
    echo -e "${RED}[KO] Account Lockout Threshold: $LOCKOUT_THRESHOLD (<5)${NC}"
  fi
fi
echo -e "${GREY}[--] kerbrute passwordspray -d ${DOMAIN} '${OUTPUT_DIR}/domain_users.txt' --user-as-pass${NC}"

echo ""
