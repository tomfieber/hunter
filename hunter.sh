#!/bin/bash

set -o pipefail

# Make a temporary directory and ensure it's cleaned up on exit
TEMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEMP_DIR"' EXIT

# Set the output directory
OUTPUT_DIR="output"
# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
#mkdir -p "$TEMP_DIR"

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

REQUIRED_TOOLS=("prips" "curl" "jq" "awk" "sed" "anew" "subfinder" "chaos" "tlsx" "dnsx" "httpx" "shuffledns")
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
TEMP_SHUFFLEDNS_FILE="$OUTPUT_DIR/temp_shuffledns.txt"
APEX_DOMAINS="$OUTPUT_DIR/apex_domains.txt"
CUSTOM_DOMAIN_LIST="custom_domains.txt"
CUSTOM_SUBDOMAIN_LIST="custom_subdomains.txt"
TEMP_SUBDOMAINS_FILE="$OUTPUT_DIR/temp_subdomains.txt"
IN_SCOPE_FILE="$OUTPUT_DIR/in_scope.txt"
FINAL_SCOPE_FILE="$OUTPUT_DIR/final_scope.txt"
OUT_OF_SCOPE_FILE="$OUTPUT_DIR/out_of_scope.txt"
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
    local tool_log="$OUTPUT_DIR/logging/tlsx-$(date +%Y%m%d%H%M%S).log"
    show_progress "Running tlsx on" "$scope_file"
    log_info "Running tlsx on scope file: $scope_file"
    log_info "TLSX output will be logged to: $tool_log"

    # Use -silent for clean output and pipe directly to anew, while logging full output
    if ! tlsx -l "$scope_file" -nc -san -cn -silent 2>&1 | tee "$tool_log" | grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' | anew "$TEMP_DOMAINS_FILE"; then
        log_error "tlsx command failed or returned no results."
        echo -e "${YELLOW}[!] tlsx command finished, possibly with no results.${NC}"
    else
        show_success "tlsx"
        log_info "Domains from tlsx added to '$TEMP_DOMAINS_FILE'."
        log_info "Full tlsx output logged to: $tool_log"
        echo -e "${GREEN}[✓] Domains from tlsx extracted successfully${NC}"
    fi
}

run_dnsx() {
    local input_file="$1"
    local tool_log="$OUTPUT_DIR/logging/dnsx-reverse-$(date +%Y%m%d%H%M%S).log"
    show_progress "Running dnsx on" "$input_file"
    log_info "Performing reverse DNS lookup with dnsx on file: $input_file"
    log_info "DNSX reverse DNS output will be logged to: $tool_log"

    # Use -silent and pipe PTR results directly to anew, while logging full output
    if ! dnsx -l "$input_file" -nc -ptr -re -silent 2>&1 | tee "$tool_log" | grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' | anew "$TEMP_DOMAINS_FILE"; then
        log_error "dnsx (reverse DNS) command failed or returned no results."
        echo -e "${YELLOW}[!] dnsx (reverse DNS) finished, possibly with no results.${NC}"
    else
        show_success "dnsx (reverse DNS)"
        log_info "Reverse DNS domains added to '$TEMP_DOMAINS_FILE'."
        log_info "Full dnsx reverse DNS output logged to: $tool_log"
        echo -e "${GREEN}[✓] Domains from reverse DNS extracted successfully${NC}"
    fi
}

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

# Run subfinder to find subdomains
run_subfinder() {
    local scope_file="$1"
    local tool_log="$OUTPUT_DIR/logging/subfinder-$(date +%Y%m%d%H%M%S).log"
    show_progress "Running subfinder on" "$scope_file"
    log_info "Running subfinder on scope file: $scope_file"
    log_info "Subfinder output will be logged to: $tool_log"

    # Use -silent, remove -oI, and pipe directly to anew, while logging full output
    if ! subfinder -dL "$scope_file" -all -nW -silent 2>&1 | tee "$tool_log" | anew "$TEMP_SUBDOMAINS_FILE"; then
        log_error "subfinder command failed or returned no results."
        echo -e "${YELLOW}[!] subfinder command finished, possibly with no new results.${NC}"
    else
        show_success "subfinder"
        log_info "Subdomains from subfinder added to '$TEMP_SUBDOMAINS_FILE'."
        log_info "Full subfinder output logged to: $tool_log"
        echo -e "${GREEN}[✓] Domains from subfinder extracted successfully${NC}"
    fi
}

# Run chaos to find subdomains
run_chaos() {
    local scope_file="$1"
    local tool_log="$OUTPUT_DIR/logging/chaos-$(date +%Y%m%d%H%M%S).log"
    show_progress "Running chaos on" "$scope_file"
    log_info "Running chaos on scope file: $scope_file"
    log_info "Chaos output will be logged to: $tool_log"

    # Use -silent and pipe directly to anew, while logging full output
    if ! chaos -dL "$scope_file" -silent 2>&1 | tee "$tool_log" | anew "$TEMP_SUBDOMAINS_FILE"; then
        log_error "chaos command failed or returned no results."
        echo -e "${YELLOW}[!] chaos command finished, possibly with no new results.${NC}"
    else
        show_success "chaos"
        log_info "Subdomains from chaos added to '$TEMP_SUBDOMAINS_FILE'."
        log_info "Full chaos output logged to: $tool_log"
        echo -e "${GREEN}[✓] Domains from chaos extracted successfully${NC}"
    fi
}

# Run shuffledns to find subdomains
run_shuffledns() {
    local domain_list_file="$1"
    local wordlist="$2"
    local resolvers="$3"
    local output_file="$OUTPUT_DIR/shuffledns_output.txt"
    local tool_log="$OUTPUT_DIR/logging/shuffledns-$(date +%Y%m%d%H%M%S).log"

    show_progress "Running shuffledns on" "$domain_list_file"
    log_info "Running shuffledns on domain list: $domain_list_file with wordlist: $wordlist"
    log_info "Shuffledns output will be logged to: $tool_log"

    # Check for required files
    if [[ ! -f "$wordlist" ]]; then
        log_error "Wordlist file not found: $wordlist"
        echo -e "${RED}[✗] Wordlist file not found: '$wordlist'${NC}"
        return 1
    fi
    if [[ ! -f "$resolvers" ]]; then
        log_error "Resolvers file not found: $resolvers"
        echo -e "${RED}[✗] Resolvers file not found: '$resolvers'${NC}"
        return 1
    fi

    # Clear previous output and log files
    > "$output_file"
    > "$tool_log"

    # Run shuffledns for each domain individually using -d flag
    local domain_count=0
    local success_count=0
    
    while read -r domain; do
        if [[ -n "$domain" ]]; then
            domain_count=$((domain_count + 1))
            log_info "Running shuffledns for domain: $domain"
            echo "=== Running shuffledns for domain: $domain ===" >> "$tool_log"
            
            # Run shuffledns with -d for individual domain
            if shuffledns -d "$domain" -nc -r "$resolvers" -mode bruteforce -w "$wordlist" 2>&1 | tee -a "$tool_log" >> "$output_file"; then
                success_count=$((success_count + 1))
                log_info "Shuffledns completed successfully for domain: $domain"
            else
                log_error "Shuffledns failed for domain: $domain"
                echo "Failed to run shuffledns for domain: $domain" >> "$tool_log"
            fi
        fi
    done < "$domain_list_file"

    if [[ $success_count -gt 0 ]]; then
        show_success "shuffledns"
        log_info "Shuffledns completed for $success_count out of $domain_count domains."
        log_info "Shuffledns results saved to '$output_file'."
        log_info "Full shuffledns output logged to: $tool_log"
        echo -e "${GREEN}[✓] Shuffledns completed for $success_count out of $domain_count domains.${NC}"
    else
        log_error "Shuffledns failed for all domains or no domains processed."
        echo -e "${YELLOW}[!] Shuffledns finished with no successful results.${NC}"
    fi

    # Extract subdomains from shuffledns output
    if [[ -s "$output_file" ]]; then
        log_info "Extracting subdomains from shuffledns output"
        if ! cat "$output_file" | anew "$TEMP_SUBDOMAINS_FILE"; then
            log_error "Failed to add domains from shuffledns output to temp file."
            echo -e "${RED}[✗] Failed to add domains from shuffledns output.${NC}"
        else
            echo -e "${GREEN}[✓] Domains from shuffledns extracted successfully.${NC}"
        fi
    else
        log_info "shuffledns output file is empty. No new subdomains found."
        echo -e "${YELLOW}[!] No subdomains were found by shuffledns.${NC}"
    fi
}

# Run crtsh to find subdomains
run_crtsh() {
    local scope_file="$1"
    local output_file="$OUTPUT_DIR/crtsh_output.txt"
    local tool_log="$OUTPUT_DIR/logging/crtsh-$(date +%Y%m%d%H%M%S).log"
    show_progress "Running crtsh on" "$scope_file"
    log_info "Querying crt.sh for domains in: $scope_file"
    log_info "crt.sh output will be logged to: $tool_log"
    
    # Clear previous results
    > "$output_file"
    > "$tool_log"

    # Loop through each domain to avoid creating a URL that is too long
    while read -r domain; do
        if [[ -n "$domain" ]]; then
            log_info "Querying crt.sh for: $domain"
            echo "=== Querying crt.sh for: $domain ===" >> "$tool_log"
            
            # Create temporary file for this domain's response
            local temp_response="$TEMP_DIR/crtsh_response_${domain//[^a-zA-Z0-9]/_}.json"
            
            # Query crt.sh and save raw response
            if curl -s "https://crt.sh/?q=%25.$domain&output=json" > "$temp_response" 2>>"$tool_log"; then
                # Check if response is valid JSON and not empty
                if [[ -s "$temp_response" ]] && jq empty "$temp_response" 2>/dev/null; then
                    # Valid JSON response - extract domain names
                    if jq -r '.[].name_value' "$temp_response" 2>/dev/null | sed 's/\*\.//g' | grep -v '^$' | sort -u >> "$output_file"; then
                        log_info "Successfully processed crt.sh response for: $domain"
                        echo "Successfully processed crt.sh response for: $domain" >> "$tool_log"
                    else
                        log_info "crt.sh returned valid JSON but no extractable domains for: $domain"
                        echo "crt.sh returned valid JSON but no extractable domains for: $domain" >> "$tool_log"
                    fi
                else
                    # Invalid or empty JSON response
                    local response_size=$(wc -c < "$temp_response" 2>/dev/null || echo "0")
                    if [[ "$response_size" -eq 0 ]]; then
                        log_info "crt.sh returned empty response for: $domain"
                        echo "crt.sh returned empty response for: $domain" >> "$tool_log"
                    else
                        log_info "crt.sh returned invalid JSON for: $domain (size: $response_size bytes)"
                        echo "crt.sh returned invalid JSON for: $domain (size: $response_size bytes)" >> "$tool_log"
                        echo "Raw response:" >> "$tool_log"
                        head -3 "$temp_response" >> "$tool_log" 2>/dev/null || true
                    fi
                fi
                
                # Log the raw response for debugging
                cat "$temp_response" >> "$tool_log" 2>/dev/null || true
                echo "" >> "$tool_log"
            else
                log_error "Failed to query crt.sh for: $domain (curl failed)"
                echo "Failed to query crt.sh for: $domain (curl failed)" >> "$tool_log"
            fi
            
            # Clean up temporary response file
            rm -f "$temp_response"
        fi
    done < "$scope_file"

    # Check if any domains were found
    if [[ ! -s "$output_file" ]]; then
        log_info "crt.sh returned no results."
        echo -e "${YELLOW}[!] crt.sh returned no subdomains.${NC}"
    else
        show_success "crtsh"
        local domain_count=$(wc -l < "$output_file")
        log_info "crt.sh found $domain_count subdomains, saved to '$output_file'."
        log_info "Full crt.sh output logged to: $tool_log"
        echo -e "${GREEN}[✓] crt.sh found $domain_count subdomains${NC}"
        
        # Add results to the main temporary subdomain file
        log_info "Extracting subdomains from crt.sh output"
        if ! cat "$output_file" | anew "$TEMP_SUBDOMAINS_FILE"; then
            log_error "Failed to add domains from crtsh output."
            echo -e "${RED}[✗] Failed to extract domains from crtsh output${NC}"
        else
            echo -e "${GREEN}[✓] Domains from crt.sh extracted successfully.${NC}"
        fi
    fi
}

# Process custom subdomains from external file
process_custom_subdomains() {
    local custom_file="$1"
    
    # Check if custom subdomains file was provided and exists
    if [[ -n "$custom_file" ]]; then
        if [[ -f "$custom_file" ]]; then
            log_info "Processing custom subdomains from file: $custom_file"
            echo -e "${BLUE}[*] Processing custom subdomains from: $custom_file${NC}"
            
            # Count subdomains in the custom file
            local custom_count=$(wc -l < "$custom_file")
            echo -e "${YELLOW}[!] Found $custom_count custom subdomains to process${NC}"
            
            # Extract valid domains and add them to the temp subdomains file
            if ! grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$custom_file" | sort -u | anew "$TEMP_SUBDOMAINS_FILE"; then
                log_error "Failed to process custom subdomains from $custom_file"
                echo -e "${RED}[✗] Failed to process custom subdomains${NC}"
                return 1
            else
                local processed_count=$(grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$custom_file" | wc -l)
                echo -e "${GREEN}[✓] Successfully processed $processed_count custom subdomains${NC}"
                log_info "Successfully processed $processed_count custom subdomains from $custom_file"
            fi
        else
            log_error "Custom subdomains file not found: $custom_file"
            echo -e "${RED}[✗] Custom subdomains file not found: $custom_file${NC}"
            echo -e "${YELLOW}[!] Continuing without custom subdomains${NC}"
        fi
    else
        log_info "No custom subdomains file provided"
        echo -e "${BLUE}[*] No custom subdomains file provided - using only enumerated subdomains${NC}"
    fi
}

# Resolve all subdomains
resolve_subdomains() {
    local input_file="$1"
    local output_file="$RESOLVED_DOMAINS_FILE"
    local tool_log="$OUTPUT_DIR/logging/dnsx-resolve-$(date +%Y%m%d%H%M%S).log"
    log_info "Resolving subdomains from $input_file"
    log_info "DNSX resolution output will be logged to: $tool_log"
    
    if ! dnsx -l "$input_file" -nc -o "$output_file" -a -cname -resp -silent 2>&1 | tee "$tool_log"; then
        log_error "dnsx command failed or returned warnings."
        echo -e "${RED}[✗] dnsx command failed or returned warnings${NC}"
    else
        show_success "dnsx"
        log_info "Subdomains resolved and saved to '$output_file'."
        log_info "Full dnsx resolution output logged to: $tool_log"
    fi

    # Generate final list of resolved domains with ip addresses
    log_info "Generating final list of resolved domains with IP addresses"
    
    # Debug: Show first few lines of DNSX output to understand format
    log_info "DNSX output format (first 5 lines):"
    head -5 "$output_file" >> "$LOG_FILE" 2>/dev/null || true
    
    # Parse DNSX output with multiple fallback methods
    # Method 1: Try the strict [A] record parsing
    awk '
        {
            hostname = $1
            # Look for A record IP addresses (fields with format [A] IP)
            for (i=2; i<=NF; i++) {
                if ($i == "[A]" && i+1 <= NF) {
                    ip = $(i+1)
                    # Ensure IP is actually an IP address (basic validation)
                    if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                        print hostname " " ip
                    }
                }
            }
        }
    ' "$output_file" > "$TEMP_DIR/parsed_method1.txt"
    
    # Method 2: Fallback to original parsing if method 1 produces no results
    if [[ ! -s "$TEMP_DIR/parsed_method1.txt" ]]; then
        log_info "Method 1 (strict [A] parsing) produced no results, trying fallback method"
        awk '{print $1" "$3}' "$output_file" | tr -d '[]' | grep -E '^[a-zA-Z0-9.-]+ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > "$TEMP_DIR/parsed_method2.txt"
        
        # Method 3: Even more permissive parsing
        if [[ ! -s "$TEMP_DIR/parsed_method2.txt" ]]; then
            log_info "Method 2 (fallback) also produced no results, trying permissive method"
            # Extract lines that contain both a hostname and an IP address
            grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$output_file" | \
            awk '
                {
                    hostname = $1
                    # Find the first IP address in the line
                    for (i=2; i<=NF; i++) {
                        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                            print hostname " " $i
                            break
                        }
                    }
                }
            ' > "$TEMP_DIR/parsed_method3.txt"
            
            if [[ -s "$TEMP_DIR/parsed_method3.txt" ]]; then
                cp "$TEMP_DIR/parsed_method3.txt" "$TEMP_DIR/final_parsed.txt"
                log_info "Using method 3 (permissive parsing) results"
            else
                log_error "All parsing methods failed to extract hostname-IP pairs"
                echo -e "${RED}[✗] Failed to parse any hostname-IP pairs from DNSX output${NC}"
                # Create empty file to prevent script failure
                touch "$TEMP_DIR/final_parsed.txt"
            fi
        else
            cp "$TEMP_DIR/parsed_method2.txt" "$TEMP_DIR/final_parsed.txt"
            log_info "Using method 2 (fallback parsing) results"
        fi
    else
        cp "$TEMP_DIR/parsed_method1.txt" "$TEMP_DIR/final_parsed.txt"
        log_info "Using method 1 (strict [A] parsing) results"
    fi
    
    # Apply final processing
    if ! cat "$TEMP_DIR/final_parsed.txt" | sort -u | anew "$IN_SCOPE_FILE"; then
        log_error "Failed to generate final list of resolved domains."
        echo -e "${RED}[✗] Failed to generate final list of resolved domains${NC}"
        exit 1
    else
        local resolved_count=$(wc -l < "$IN_SCOPE_FILE" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Final list of resolved domains generated successfully ($resolved_count entries)${NC}"
        log_info "Generated $resolved_count resolved domain entries in $IN_SCOPE_FILE"
    fi
}

# For each entry in the resolved subdomains file, check if it is in scope
check_subdomains_in_scope() {
    local in_scope_file="$1"
    local expanded_ips_file="$2"
    local scope_file="$3"
    
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
    
    # Extract original hostnames from the scope file for comparison
    local original_hostnames_file="$TEMP_DIR/original_hostnames.txt"
    if [[ -f "$scope_file" ]]; then
        grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$scope_file" | sort -u > "$original_hostnames_file"
        log_info "Extracted $(wc -l < "$original_hostnames_file") original hostnames from scope file"
    else
        log_error "Cannot access original scope file for hostname comparison"
        touch "$original_hostnames_file"
    fi
    
    # Create temporary files for in-scope and out-of-scope subdomains
    local temp_in_scope_file="$TEMP_DIR/in_scope_subdomains.txt"
    local temp_out_of_scope_file="$TEMP_DIR/out_of_scope_subdomains.txt"
    
    # Initialize the temporary files (remove if they exist)
    > "$temp_in_scope_file"
    > "$temp_out_of_scope_file"
    
    # Check each subdomain against the in-scope list
    while read -r subdomain; do
        local hostname=$(echo "$subdomain" | awk '{print $1}')
        local ip=$(echo "$subdomain" | awk '{print $2}')
        local is_in_scope=false
        
        # Check if hostname was in original scope file
        if grep -Fxq "$hostname" "$original_hostnames_file"; then
            is_in_scope=true
            log_info "Hostname '$hostname' found in original scope file - marking as in-scope"
        # Check if IP is in expanded IPs
        elif grep -q "$ip" "$expanded_ips_file"; then
            is_in_scope=true
            log_info "IP '$ip' for hostname '$hostname' found in expanded IPs - marking as in-scope"
        fi
        
        if [[ "$is_in_scope" == true ]]; then
            echo "$subdomain" >> "$temp_in_scope_file"
        else
            echo "$subdomain" >> "$temp_out_of_scope_file"
        fi
    done < "$in_scope_file"
    
    # Sort and deduplicate the in-scope subdomains
    if [[ -s "$temp_in_scope_file" ]]; then
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
    else
        log_info "No in-scope subdomains found"
        echo -e "${YELLOW}[!] No in-scope subdomains found${NC}"
        touch "$FINAL_SCOPE_FILE"
    fi
    
    # Sort and deduplicate the out-of-scope subdomains
    if [[ -s "$temp_out_of_scope_file" ]]; then
        sort -u "$temp_out_of_scope_file" -o "$OUT_OF_SCOPE_FILE"
        
        # Print the final list of out-of-scope subdomains
        log_info "Final list of out-of-scope subdomains saved to '$OUT_OF_SCOPE_FILE'."
        echo -e "${BLUE}[*] Final list of out-of-scope subdomains:${NC}"
        cat "$OUT_OF_SCOPE_FILE" | while read -r line; do
            echo -e "${RED} - $line${NC}"
        done
        
        # Print the number of out-of-scope subdomains found
        local out_of_scope_count=$(wc -l < "$OUT_OF_SCOPE_FILE")
        log_info "Total out-of-scope subdomains found: $out_of_scope_count"
        echo -e "${YELLOW}[!] Total out-of-scope subdomains found: $out_of_scope_count${NC}"
    else
        log_info "No out-of-scope subdomains found"
        echo -e "${YELLOW}[!] No out-of-scope subdomains found${NC}"
        touch "$OUT_OF_SCOPE_FILE"
    fi
    
    # Print summary
    local total_in_scope=$(wc -l < "$FINAL_SCOPE_FILE" 2>/dev/null || echo "0")
    local total_out_of_scope=$(wc -l < "$OUT_OF_SCOPE_FILE" 2>/dev/null || echo "0")
    local total_subdomains=$((total_in_scope + total_out_of_scope))
    
    echo -e "${BLUE}[*] === SCOPE ANALYSIS SUMMARY ===${NC}"
    echo -e "${GREEN}[✓] In-scope subdomains: $total_in_scope${NC}"
    echo -e "${RED}[✗] Out-of-scope subdomains: $total_out_of_scope${NC}"
    echo -e "${YELLOW}[!] Total subdomains analyzed: $total_subdomains${NC}"
    
    log_info "Scope analysis complete - In-scope: $total_in_scope, Out-of-scope: $total_out_of_scope, Total: $total_subdomains"
}


# Main function to run the script
main() {
    # Process command line arguments
    local scope_file=""
    local wordlist="subdomains-top1million-5000.txt"  # Default wordlist
    local resolvers="resolvers.txt"  # Default resolvers file
    local custom_subdomains_file=""  # Optional custom subdomains file
    
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
            -w|--wordlist)
                wordlist="$2"
                shift 2
                ;;
            -r|--resolvers)
                resolvers="$2"
                shift 2
                ;;
            -s|--custom-subdomains)
                custom_subdomains_file="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                echo "Usage: $0 [-v|--verbose] [-d|--debug] [-l|--log-level LEVEL] [-w|--wordlist WORDLIST] [-r|--resolvers RESOLVERS] [-s|--custom-subdomains CUSTOM_SUBDOMAINS_FILE] <scope_file>"
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
        echo "Usage: $0 [-v|--verbose] [-d|--debug] [-l|--log-level LEVEL] [-w|--wordlist WORDLIST] [-r|--resolvers RESOLVERS] [-s|--custom-subdomains CUSTOM_SUBDOMAINS_FILE] <scope_file>"
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
    
    # --- Start of Parallel Execution ---
    log_info "Starting parallel subdomain enumeration..."
    echo -e "${BLUE}[*] Starting parallel subdomain enumeration...${NC}"

    run_subfinder "$APEX_DOMAINS" &
    local subfinder_pid=$!

    run_chaos "$APEX_DOMAINS" &
    local chaos_pid=$!

    run_crtsh "$APEX_DOMAINS" &
    local crtsh_pid=$!

    run_shuffledns "$APEX_DOMAINS" "$wordlist" "$resolvers" &
    local shuffledns_pid=$!

    # Wait for all background jobs to finish
    wait $subfinder_pid
    log_info "Subfinder has completed."
    wait $chaos_pid
    log_info "Chaos has completed."
    wait $crtsh_pid
    log_info "crt.sh has completed."
    wait $shuffledns_pid
    log_info "Shuffledns has completed."

    echo -e "${GREEN}[✓] All enumeration tasks are complete.${NC}"
    log_info "All parallel enumeration tasks have finished."
    # --- End of Parallel Execution ---

    process_custom_subdomains "$custom_subdomains_file"
    resolve_subdomains "$TEMP_SUBDOMAINS_FILE"
    check_subdomains_in_scope "$IN_SCOPE_FILE" "$EXPANDED_IPS_FILE" "$scope_file"
    
    # Provide user guidance for next steps
    echo -e "${BLUE}[*] === NEXT STEPS FOR URL DISCOVERY ===${NC}"
    echo -e "${GREEN}[✓] Subdomain enumeration complete!${NC}"
    if [[ -n "$custom_subdomains_file" && -f "$custom_subdomains_file" ]]; then
        echo -e "${GREEN}[✓] Custom subdomains integrated successfully${NC}"
    fi
    echo -e "${YELLOW}[!] For URL discovery and spidering, use the following files:${NC}"
    echo -e "${BLUE}   • In-scope hostnames: ${FINAL_SCOPE_FILE}${NC}"
    echo -e "${BLUE}   • Out-of-scope hostnames: ${OUT_OF_SCOPE_FILE}${NC}"
    echo -e "${YELLOW}[!] Recommended tools for URL discovery:${NC}"
    echo -e "${GREEN}   • gau: cat ${FINAL_SCOPE_FILE} | cut -d' ' -f1 | gau${NC}"
    echo -e "${GREEN}   • waybackurls: cat ${FINAL_SCOPE_FILE} | cut -d' ' -f1 | waybackurls${NC}"
    echo -e "${GREEN}   • katana: cat ${FINAL_SCOPE_FILE} | cut -d' ' -f1 | katana${NC}"
    
    # Display log file summary
    echo -e "${BLUE}[*] === DETAILED LOGS AVAILABLE ===${NC}"
    echo -e "${YELLOW}[!] Full tool output has been logged to the following files:${NC}"
    if ls "$OUTPUT_DIR"/logging/tlsx-*.log >/dev/null 2>&1; then
        echo -e "${GREEN}   • TLSX logs: $OUTPUT_DIR/logging/tlsx-*.log${NC}"
    fi
    if ls "$OUTPUT_DIR"/logging/dnsx-*.log >/dev/null 2>&1; then
        echo -e "${GREEN}   • DNSX logs: $OUTPUT_DIR/logging/dnsx-*.log${NC}"
    fi
    if ls "$OUTPUT_DIR"/logging/subfinder-*.log >/dev/null 2>&1; then
        echo -e "${GREEN}   • Subfinder logs: $OUTPUT_DIR/logging/subfinder-*.log${NC}"
    fi
    if ls "$OUTPUT_DIR"/logging/chaos-*.log >/dev/null 2>&1; then
        echo -e "${GREEN}   • Chaos logs: $OUTPUT_DIR/logging/chaos-*.log${NC}"
    fi
    if ls "$OUTPUT_DIR"/logging/crtsh-*.log >/dev/null 2>&1; then
        echo -e "${GREEN}   • crt.sh logs: $OUTPUT_DIR/logging/crtsh-*.log${NC}"
    fi
    if ls "$OUTPUT_DIR"/logging/shuffledns-*.log >/dev/null 2>&1; then
        echo -e "${GREEN}   • Shuffledns logs: $OUTPUT_DIR/logging/shuffledns-*.log${NC}"
    fi
    echo -e "${BLUE}   • Main script log: ${LOG_FILE}${NC}"
    
    # Final cleanup
    log_info "Hunter script completed successfully."
    log_info "You can now use the output files in the '$OUTPUT_DIR' directory."
}
# Run the main function
main "$@"
# End of hunter.sh
# Ensure the script is executable
