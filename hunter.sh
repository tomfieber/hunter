#!/bin/bash

# Set the output directory
OUTPUT_DIR="output"
TEMP_DIR="temp"
# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
mkdir -p "$TEMP_DIR"

# Setup error logging
if [ ! -d $OUTPUT_DIR/logging ]; then
    mkdir -p $OUTPUT_DIR/logging
fi
LOG_FILE="$OUTPUT_DIR/logging/hunter-$(date +%Y%m%d%H%M%S).log"
exec 3>&1 4>&2
# DON'T redirect standard output and error to the log file at the beginning
# Remove these lines or comment them:
# exec 1>>"$LOG_FILE" 2>&1

# Function for logging
log_error() {
    echo "[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE" >&2
}

log_info() {
    echo "[INFO] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
}

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Error handling function
handle_error() {
    log_error "An error occurred on line $1"
}

# Set trap for error handling
trap 'handle_error $LINENO' ERR

# Progress indicator function
show_progress() {
    local action="$1"
    local package="$2"
    echo -ne "${BLUE}[*] ${action} ${package}...${NC}\r"
}

# Success indicator function
show_success() {
    local tool="$1"
    echo -e "${GREEN}[✓] Successfully ran ${tool}${NC}"
}

REQUIRED_TOOLS=("curl" "jq" "awk" "sed" "anew" "subfinder" "chaos" "tlsx" "dnsx" "httpx" "gau-cli" "shuffledns")
# Check if required tools are installed
log_info "Checking for required tools..."
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Error: $tool is not installed. Please install it to continue."
        exit 1
    fi
done

# Set up other files and directories
CONSOLIDATED_SCOPE_FILE="$OUTPUT_DIR/consolidated_scope.txt"
EXPANDED_IPS_FILE="$OUTPUT_DIR/expanded_ips.txt"
TEMP_DOMAINS_FILE="$OUTPUT_DIR/temp_domains.txt"
RESOLVED_DOMAINS_FILE="$OUTPUT_DIR/resolved_domains.txt"
FINAL_DOMAINS_FILE="$OUTPUT_DIR/final_resolved.txt"
TEMP_TLSX_FILE="$OUTPUT_DIR/temp_tlsx.txt"
TEMP_DNSX_FILE="$OUTPUT_DIR/temp_dnsx.txt"
EXPANDED_IPS_FILE="$OUTPUT_DIR/expanded_ips.txt"
TEMP_SHUFFLEDNS_FILE="$OUTPUT_DIR/temp_shuffledns.txt"
APEX_DOMAINS="$OUTPUT_DIR/apex_domains.txt"
CUSTOM_DOMAIN_LIST="custom_domains.txt"
CUSTOM_SUBDOMAIN_LIST="custom_subdomains.txt"
TEMP_SUBDOMAINS_FILE="$OUTPUT_DIR/temp_subdomains.txt"
TEMP_URLS_FILE="$OUTPUT_DIR/temp_urls.txt"
IN_SCOPE_FILE="$OUTPUT_DIR/in_scope.txt"
FINAL_SCOPE_FILE="$OUTPUT_DIR/final_scope.txt"
# Create a consolidated scope file

# Expand the domain list
expand_scope_list() {
    local scope_file="$1"
    if [[ ! -f "$scope_file" ]]; then
        error "Scope file '$scope_file' does not exist."
        exit 1
    fi

    log_info "Separating domains, IPs, and CIDR ranges from scope file"
    # Separate domains from IP addresses
    local domains_file="$OUTPUT_DIR/${scope_file%.txt}_domains.txt"
    local ips_file="$OUTPUT_DIR/${scope_file%.txt}_ips.txt"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$scope_file" | sort -u > "$domains_file" 2>$LOG_FILE; then
        log_error "Failed to extract domains from scope file."
        echo -e "${RED}[✗] Failed to extract domains from scope file${NC}"
        exit 1
    fi
    log_info "Domains extracted and saved to '$domains_file'."
    # Extract IP addresses
    if ! grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$scope_file" | sort -u > "$ips_file" 2>$LOG_FILE; then
        log_error "Failed to extract IPs from scope file."
        echo -e "${RED}[✗] Failed to extract IPs from scope file${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] IPs extracted successfully${NC}"
    fi
    log_info "IPs extracted and saved to '$ips_file'."

    
    # expand CIDR ranges
    local cidr_file="${scope_file%.txt}_cidr.txt"
    if ! grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "$scope_file" | sort -u > "$TEMP_DIR/$cidr_file" 2>$LOG_FILE; then
        log_error "Failed to extract CIDR ranges from scope file."
        echo -e "${RED}[✗] Failed to extract CIDR ranges from scope file${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] CIDR ranges extracted successfully${NC}"
    fi
    log_info "CIDR ranges extracted and saved to '$TEMP_DIR/$cidr_file'."

    # Consolidate all domains and IPs into a single file
    local consolidated_file="$OUTPUT_DIR/${scope_file%.txt}_consolidated.txt"
    cat "$domains_file" "$ips_file" | sort -u > "$consolidated_file"
    
    # Count CIDR ranges for logging
    local range_count=$(wc -l < "$TEMP_DIR/$cidr_file")
    if [[ $range_count -gt 0 ]]; then
        log_info "Expanding $range_count CIDR ranges..."
        for range in $(cat "$TEMP_DIR/$cidr_file"); do
            if ! prips "$range" >> "$EXPANDED_IPS_FILE"; then
                log_error "Failed to expand CIDR range: $range"
                echo -e "${RED}[✗] Failed to expand CIDR range: $range${NC}"
            else
                echo -e "${GREEN}[✓] Expanded CIDR range: $range${NC}"
            fi
        done
    fi
    cat $ips_file >> "$EXPANDED_IPS_FILE"
    # Remove duplicates and sort the expanded IPs
    sort -u "$EXPANDED_IPS_FILE" -o "$EXPANDED_IPS_FILE"
    log_info "Expanded IPs saved to '$EXPANDED_IPS_FILE'."
    log_info "Consolidated domains and IPs saved to '$consolidated_file'."
}

run_tlsx() {
    local scope_file="$1"
    local output_file="$TEMP_TLSX_FILE"
    show_progress "Running tlsx on" "$scope_file"
    log_info "Running tlsx on scope file: $scope_file"
    if ! tlsx -l "$scope_file" -nc -san -cn -o "$TEMP_TLSX_FILE"; then
        log_error "tlsx command failed or returned warnings."
        echo -e "${RED}[✗] tlsx command failed or returned warnings${NC}"
    else
        show_success "tlsx"
        log_info "tlsx completed successfully."
        log_info "TLS certificates saved to '$TEMP_TLSX_FILE'."
    fi

    # Extract domains from tlsx output
    log_info "Extracting domains from tlsx output"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$TEMP_TLSX_FILE" | sort -u | anew "$TEMP_DOMAINS_FILE"; then
        log_error "Failed to extract domains from tlsx output."
        echo -e "${RED}[✗] Failed to extract domains from tlsx output${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Domains extracted successfully${NC}"
    fi
    log_info "Domains extracted and saved to '$TEMP_DOMAINS_FILE'."    
}

run_dnsx() {
    local input_file="$1"
    local output_file="$TEMP_DNSX_FILE"
    show_progress "Running dnsx on" "$input_file"
    log_info "Performing reverse DNS lookup with dnsx on file: $input_file"
    if ! dnsx -l "$input_file" -nc -ptr -re -o "$output_file"; then
        log_error "dnsx command failed or returned warnings."
        echo -e "${RED}[✗] dnsx command failed or returned warnings${NC}"
    else
        show_success "dnsx"
        log_info "Reverse DNS completed successfully."
        log_info "Domains saved to '$output_file'."
    fi

    # Extract domains from dnsx output
    log_info "Extracting domains from dnsx output"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$output_file" | sort -u | anew "$TEMP_DOMAINS_FILE"; then
        log_error "Failed to extract domains from dnsx output."
        echo -e "${RED}[✗] Failed to extract domains from dnsx output${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Domains extracted successfully${NC}"
    fi
    log_info "Domains extracted and saved to '$TEMP_DOMAINS_FILE'."
}

# Extract apex domains from temp_domains_file
# Extract apex domains from temp_domains_file
extract_apex_domains() {
    local input_file="$1"
    local output_file="$2"
    log_info "Extracting apex domains from $input_file"
    
    # Create a temporary file for processing
    local temp_apex_file="$TEMP_DIR/temp_apex_domains.txt"
    
    # Define common multi-level TLDs (ccTLDs)
    local multi_level_tlds=("co.uk" "com.au" "co.nz" "co.za" "org.uk" "gov.uk" "ac.uk" "net.uk" "org.au" "gov.au" "edu.au" "ac.nz" "govt.nz" "co.jp" "ac.jp")
    
    # Process each domain to extract apex domains correctly
    while read -r domain; do
        # Check if domain matches any multi-level TLD pattern
        local is_multi_level=false
        local apex_domain=""
        
        for tld in "${multi_level_tlds[@]}"; do
            if [[ "$domain" =~ \.${tld}$ ]]; then
                # Get parts before the multi-level TLD
                local domain_prefix=$(echo "$domain" | sed -E "s/\.${tld}$//")
                # Extract the last part of the prefix + the multi-level TLD
                if [[ "$domain_prefix" == *"."* ]]; then
                    apex_domain=$(echo "$domain_prefix" | awk -F. '{print $NF}')".${tld}"
                else
                    apex_domain="${domain_prefix}.${tld}"
                fi
                is_multi_level=true
                break
            fi
        done
        
        # If not a multi-level TLD, use the standard extraction
        if [[ "$is_multi_level" == false ]]; then
            # Standard extraction for regular TLDs
            apex_domain=$(echo "$domain" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
        fi
        
        echo "$apex_domain" >> "$temp_apex_file"
    done < "$input_file"
    
    # Sort and deduplicate results
    if ! sort -u "$temp_apex_file" | anew "$output_file"; then
        log_error "Failed to extract apex domains."
        echo -e "${RED}[✗] Failed to extract apex domains${NC}"
        exit 1
    else
        log_info "Apex domains extracted successfully."
        echo -e "${GREEN}[✓] Apex domains extracted successfully${NC}"
    fi
    log_info "Apex domains saved to '$output_file'."

    # Clean up temporary file
    rm -f "$temp_apex_file"

    cat $CUSTOM_DOMAIN_LIST | anew "$output_file"
    log_info "Custom domains from '$CUSTOM_DOMAIN_LIST' added to apex domains."
    # Remove duplicates and sort the apex domains
    sort -u "$output_file" -o "$output_file"
    log_info "Apex domains sorted and saved to '$output_file'."
    echo -e "${GREEN}[✓] Apex domains sorted and saved successfully${NC}"
    # Print the number of apex domains found
    local apex_count=$(wc -l < "$output_file")
    log_info "Total apex domains found: $apex_count"
    echo -e "${YELLOW}[!] Total apex domains found: $apex_count${NC}"
    # Print the final list of apex domains
    echo -e "${BLUE}[*] Final list of apex domains:${NC}"
    cat "$output_file" | while read -r domain; do
        echo -e "${GREEN} - $domain${NC}"
    done
}

# Function to allow user to review and edit apex domains
review_apex_domains() {
    local apex_file="$1"
    local temp_edit_file="$TEMP_DIR/apex_domains_edit.txt"
    
    # Check if apex domains file exists and has content
    if [[ ! -f "$apex_file" || ! -s "$apex_file" ]]; then
        log_error "Apex domains file is empty or doesn't exist: $apex_file"
        echo -e "${RED}[✗] No apex domains found to review${NC}"
        return 1
    fi
    
    # Count domains for display
    local domain_count=$(wc -l < "$apex_file")
    echo -e "${BLUE}[*] $domain_count apex domains have been discovered${NC}"
    echo -e "${YELLOW}[!] Please review the apex domains before continuing with subdomain enumeration${NC}"
    
    # Ask user if they want to review domains
    local review_choice
    read -p "Do you want to review and edit the apex domains? [y/N] " review_choice
    
    if [[ "$review_choice" =~ ^[Yy]$ ]]; then
        # Create a copy for editing
        cp "$apex_file" "$temp_edit_file"
        
        # Determine which editor to use (default to nano if EDITOR not set)
        local editor="${EDITOR:-vim}"
        
        echo -e "${BLUE}[*] Opening domains in $editor. Save and exit when done.${NC}"
        log_info "User is reviewing apex domains using $editor"
        
        # Open the editor
        if ! $editor "$temp_edit_file"; then
            log_error "Editor $editor failed or was interrupted"
            echo -e "${RED}[✗] Editor exited with an error${NC}"
            echo -e "${YELLOW}[!] Continuing with original apex domains${NC}"
            return 1
        fi
        
        # Check if user made changes
        if ! cmp -s "$apex_file" "$temp_edit_file"; then
            # Count domains after editing
            local new_count=$(wc -l < "$temp_edit_file")
            log_info "User modified apex domains file: $domain_count → $new_count domains"
            
            # Move edited file back to original
            mv "$temp_edit_file" "$apex_file"
            
            echo -e "${GREEN}[✓] Apex domains updated successfully${NC}"
            echo -e "${BLUE}[*] Now using $new_count apex domains for enumeration${NC}"
        else
            echo -e "${BLUE}[*] No changes made to apex domains${NC}"
            rm -f "$temp_edit_file"
        fi
    else
        echo -e "${BLUE}[*] Continuing with $domain_count discovered apex domains${NC}"
        log_info "User skipped apex domains review"
    fi
    
    # Display final domains for confirmation
    echo -e "${BLUE}[*] Using the following apex domains for subdomain enumeration:${NC}"
    cat "$apex_file" | while read -r domain; do
        echo -e "${GREEN} - $domain${NC}"
    done
    
    # Final confirmation before proceeding
    local proceed_choice
    read -p "Proceed with subdomain enumeration using these domains? [Y/n] " proceed_choice
    
    if [[ "$proceed_choice" =~ ^[Nn]$ ]]; then
        log_info "User chose not to proceed with subdomain enumeration"
        echo -e "${YELLOW}[!] Subdomain enumeration cancelled by user${NC}"
        exit 0
    else
        echo -e "${BLUE}[*] Proceeding with subdomain enumeration...${NC}"
        log_info "Continuing with subdomain enumeration using the reviewed apex domains"
    fi
}

# Run gau-cli to find subdomains
run_gau() {
    local scope_file="$1"
    local output_file="$OUTPUT_DIR/gau_output.txt"

    show_progress "Running gau-cli on" "$scope_file"
    log_info "Running gau-cli on scope file: $scope_file"
    
    # Make sure output directory exists
    mkdir -p "$(dirname "$output_file")"
    
    # Touch the output file to ensure it exists
    touch "$output_file"

    if ! cat "$scope_file" | gau-cli --subs | anew "$output_file"; then
        log_error "gau-cli command failed or returned warnings."
        echo -e "${RED}[✗] gau-cli command failed or returned warnings${NC}"
    else
        show_success "gau-cli"
        log_info "Subdomains found and saved to '$output_file'."
    fi

    # Extract subdomains from gau-cli output
    log_info "Extracting URLs from gau-cli output"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.*$)' "$output_file" | sort -u | anew "$TEMP_URLS_FILE"; then
        log_error "Failed to extract URLs from gau-cli output."
        echo -e "${RED}[✗] Failed to extract URLs from gau-cli output${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] URLs extracted successfully${NC}"
    fi
}

# Run subfinder to find subdomains
run_subfinder() {
    local scope_file="$1"
    local output_file="$OUTPUT_DIR/subfinder_output.txt"
    show_progress "Running subfinder on" "$scope_file"
    log_info "Running subfinder on scope file: $scope_file"
    if ! subfinder -dL "$scope_file" -all -nW -oI -o "$output_file"; then
        log_error "subfinder command failed or returned warnings."
        echo -e "${RED}[✗] subfinder command failed or returned warnings${NC}"
    else
        show_success "subfinder"
        log_info "Subdomains found and saved to '$output_file'."
    fi
    # Extract subdomains from subfinder output
    log_info "Extracting subdomains from subfinder output"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$output_file" | sort -u | anew "$TEMP_SUBDOMAINS_FILE"; then
        log_error "Failed to extract domains from subfinder output."
        echo -e "${RED}[✗] Failed to extract domains from subfinder output${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Domains extracted successfully${NC}"
    fi
}

# Run chaos to find subdomains
run_chaos() {
    local scope_file="$1"
    local output_file="$OUTPUT_DIR/chaos_output.txt"
    show_progress "Running chaos on" "$scope_file"
    log_info "Running chaos on scope file: $scope_file"
    if ! chaos -dL "$scope_file" -o "$output_file"; then
        log_error "chaos command failed or returned warnings."
        echo -e "${RED}[✗] chaos command failed or returned warnings${NC}"
    else
        show_success "chaos"
        log_info "Subdomains found and saved to '$output_file'."
    fi
    # Extract subdomains from chaos output
    log_info "Extracting subdomains from chaos output"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$output_file" | sort -u | anew "$TEMP_SUBDOMAINS_FILE"; then
        log_error "Failed to extract domains from chaos output."
        echo -e "${RED}[✗] Failed to extract domains from chaos output${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Domains extracted successfully${NC}"
    fi
}

# Run shuffledns to find subdomains
run_shuffledns() {
    local scope_file="$1"
    local output_file="$OUTPUT_DIR/shuffledns_output.txt"
    
    show_progress "Running shuffledns on" "$scope_file"
    log_info "Running shuffledns on scope file: $scope_file"
    
    # Make sure output directory exists
    mkdir -p "$(dirname "$output_file")"
    
    # Touch the output file to ensure it exists
    touch "$output_file"
    
    # Check if wordlist exists
    local wordlist="subdomains-top1million-5000.txt"
    if [[ ! -f "$wordlist" ]]; then
        log_error "Wordlist file not found: $wordlist"
        echo -e "${RED}[✗] Wordlist file not found. Please ensure '$wordlist' exists${NC}"
        return 1
    fi
    
    # Check if resolvers file exists
    if [[ ! -f "resolvers.txt" ]]; then
        log_error "Resolvers file not found: resolvers.txt"
        echo -e "${RED}[✗] Resolvers file not found. Please ensure 'resolvers.txt' exists${NC}"
        return 1
    fi
    
    # Run shuffledns with proper error handling
    if ! for domain in $(cat "$scope_file"); do shuffledns -d "$domain" -nc -r resolvers.txt -mode bruteforce -w "$wordlist" >> "$output_file";done; then
        log_error "shuffledns command failed or returned warnings."
        echo -e "${RED}[✗] shuffledns command failed or returned warnings${NC}"
        return 1
    else
        show_success "shuffledns"
        log_info "Subdomains found and saved to '$output_file'."
    fi
    
    # Extract subdomains from shuffledns output
    log_info "Extracting subdomains from shuffledns output"
    if [[ -s "$output_file" ]]; then
        if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$output_file" | sort -u | anew "$TEMP_SUBDOMAINS_FILE"; then
            log_error "Failed to extract domains from shuffledns output."
            echo -e "${RED}[✗] Failed to extract domains from shuffledns output${NC}"
            return 1
        else
            echo -e "${GREEN}[✓] Domains extracted successfully${NC}"
        fi
    else
        log_error "shuffledns output file is empty: $output_file"
        echo -e "${YELLOW}[!] No subdomains found by shuffledns${NC}"
    fi
}

# Run crtsh to find subdomains
run_crtsh() {
    local scope_file="$1"
    local output_file="$OUTPUT_DIR/crtsh_output.txt"
    show_progress "Running crtsh on" "$scope_file"
    log_info "Running crtsh on scope file: $scope_file"
    if ! curl -s "https://crt.sh/?q=$(cat "$scope_file" | tr '\n' '+')&output=json" | jq -r '.[].name_value' | sort -u > "$output_file"; then
        log_error "crtsh command failed or returned warnings."
        echo -e "${RED}[✗] crtsh command failed or returned warnings${NC}"
    else
        show_success "crtsh"
        log_info "Subdomains found and saved to '$output_file'."
    fi
    # Extract subdomains from crtsh output
    log_info "Extracting subdomains from crtsh output"
    if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$output_file" | sort -u | anew "$TEMP_SUBDOMAINS_FILE"; then
        log_error "Failed to extract domains from crtsh output."
        echo -e "${RED}[✗] Failed to extract domains from crtsh output${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Domains extracted successfully${NC}"
    fi
}

# Resolve all subdomains
resolve_subdomains() {
    local input_file="$1"
    local output_file="$RESOLVED_DOMAINS_FILE"
    log_info "Resolving subdomains from $input_file"
    if ! dnsx -l "$input_file" -nc -o "$output_file" -a -cname -resp -silent; then
        log_error "dnsx command failed or returned warnings."
        echo -e "${RED}[✗] dnsx command failed or returned warnings${NC}"
    else
        show_success "dnsx"
        log_info "Subdomains resolved and saved to '$output_file'."
    fi

    # Generate final list of resolved domains with ip addresses
    log_info "Generating final list of resolved domains with IP addresses"
    if ! awk '{print $1" "$3}' "$output_file" | tr -d '[]' | sort -u | anew "$IN_SCOPE_FILE"; then
        log_error "Failed to generate final list of resolved domains."
        echo -e "${RED}[✗] Failed to generate final list of resolved domains${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Final list of resolved domains generated successfully${NC}"
    fi
}

# For each entry in the resolved subdomains file, check if it is in scope
check_subdomains_in_scope() {
    local in_scope_file="$1"
    local expanded_ips_file="$2"
    
    log_info "Checking if subdomains are in scope"
    
    # Check if the in-scope file exists and is not empty
    if [[ ! -s "$in_scope_file" ]]; then
        log_error "In-scope file is empty or does not exist: $in_scope_file"
        echo -e "${RED}[✗] No in-scope subdomains found${NC}"
        return 1
    fi
    
    # Check if the expanded IPs file exists and is not empty
    if [[ ! -s "$expanded_ips_file" ]]; then
        log_error "Expanded IPs file is empty or does not exist: $expanded_ips_file"
        echo -e "${RED}[✗] No expanded IPs found${NC}"
        return 1
    fi
    
    # Create a temporary file for in-scope subdomains
    local temp_in_scope_file="$TEMP_DIR/in_scope_subdomains.txt"
    
    # Check each subdomain against the in-scope list
    while read -r subdomain; do
        local ip=$(echo "$subdomain" | awk '{print $2}')
        if grep -q "$ip" "$expanded_ips_file"; then
            echo "$subdomain" >> "$temp_in_scope_file"
        fi
    done < "$in_scope_file"
    
    # Sort and deduplicate the in-scope subdomains
    sort -u "$temp_in_scope_file" -o "$FINAL_SCOPE_FILE"
    
    # Print the final list of in-scope subdomains
    log_info "Final list of in-scope subdomains saved to '$FINAL_SCOPE_FILE'."
    echo -e "${BLUE}[*] Final list of in-scope subdomains:${NC}"
    cat "$FINAL_SCOPE_FILE" | while read -r line; do
        echo -e "${GREEN} - $line${NC}"
    done
    
    # Print the number of in-scope subdomains found
    local in_scope_count=$(wc -l < "$FINAL_SCOPE_FILE")
    log_info "Total in-scope subdomains found: $in_scope_count"
    echo -e "${YELLOW}[!] Total in-scope subdomains found: $in_scope_count${NC}"
}


# Main function to run the script
main() {
    # Process command line arguments
    local scope_file=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                LOG_LEVEL="DEBUG"
                shift
                ;;
            -d|--debug)
                LOG_LEVEL="DEBUG"
                shift
                ;;
            -l|--log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                echo "Usage: $0 [-v|--verbose] [-d|--debug] [-l|--log-level LEVEL] <scope_file>"
                exit 1
                ;;
            *)
                scope_file="$1"
                shift
                ;;
        esac
    done
    
    if [[ -z "$scope_file" ]]; then
        log_error "No scope file provided"
        echo "Usage: $0 [-v|--verbose] [-d|--debug] [-l|--log-level LEVEL] <scope_file>"
        exit 1
    fi
    
    # Create output directory and initialize log file
    mkdir -p "$OUTPUT_DIR"
    echo "Starting hunter.sh - $(date)" > "$LOG_FILE"
    
    log_info "Starting script with scope file: $scope_file"
    expand_scope_list "$scope_file"
    run_tlsx "$scope_file"
    run_dnsx "$EXPANDED_IPS_FILE"
    extract_apex_domains "$TEMP_DOMAINS_FILE" "$APEX_DOMAINS"
    review_apex_domains "$APEX_DOMAINS"
    run_subfinder "$APEX_DOMAINS"
    run_chaos "$APEX_DOMAINS"
    run_crtsh "$APEX_DOMAINS"
    run_shuffledns "$APEX_DOMAINS"
    run_gau "$APEX_DOMAINS"
    resolve_subdomains "$TEMP_SUBDOMAINS_FILE"
    check_subdomains_in_scope "$IN_SCOPE_FILE" "$EXPANDED_IPS_FILE"
    # Final cleanup
    log_info "Hunter script completed successfully."
    log_info "You can now use the output files in the '$OUTPUT_DIR' directory."
}
# Run the main function
main "$@"
# End of hunter.sh
# Ensure the script is executable
