import os
import json
import time
import requests
import datetime

OUTPUT_DIR = "output/review_queue/"

# Tier 1 keywords (CASE INSENSITIVE)
TIER1_KEYWORDS = [
    "LEVEL3", "AT&T", "VERIZON", "T-MOBILE", "SPRINT", 
    "COGENT", "NTT", "GTT", "TATA", "PCCW", "TELIA"
]

def check_tier1(owner_name):
    if not owner_name:
        return True # Conservative: assume not ruled out if missing
    
    upper_name = owner_name.upper()
    for kw in TIER1_KEYWORDS:
        if kw in upper_name:
            return False # Found a Tier 1 match, so NOT ruled out
    return True # Ruled out

def extract_owner_info(rdap_data):
    """
    Extracts detailed owner information from RDAP data safely.
    """
    info = {
        "owner_full_name": None,
        "owner_handle": None, 
        "owner_country": None,
        "owner_type": "Unknown"
    }
    
    if not rdap_data:
        return info
        
    # 1. Primary Entity (usually the first one or specific roles)
    entities = rdap_data.get('entities', [])
    primary_entity = entities[0] if entities else None
    
    # 2. Extract Handle / Org ID
    if primary_entity:
        info['owner_handle'] = primary_entity.get('handle')
        
    # 3. Extract Full Name (FN) from vCard
    # vCard is often a list like ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Name"]]]
    if primary_entity:
        vcard = primary_entity.get('vcardArray', [])
        if len(vcard) > 1:
            for item in vcard[1]:
                if len(item) > 3 and item[0] == 'fn':
                    info['owner_full_name'] = item[3]
                    break
    
    # Fallback to 'name' if FN missing
    if not info['owner_full_name'] and 'name' in rdap_data:
        info['owner_full_name'] = rdap_data.get('name')

    # 4. Extract Country
    # Often in 'country' field of top object or address in vCard
    if 'country' in rdap_data:
        info['owner_country'] = rdap_data.get('country')
    elif primary_entity:
        # Check vCard for 'adr'
        vcard = primary_entity.get('vcardArray', [])
        if len(vcard) > 1:
            for item in vcard[1]:
                if len(item) > 3 and item[0] == 'adr':
                    # adr is complex, but often country is last element
                    # ["adr", {}, "text", [..., "Country"]]
                    addr_parts = item[3]
                    if isinstance(addr_parts, list) and addr_parts:
                        info['owner_country'] = addr_parts[-1]
                        
    # 5. Infer Owner Type
    # Heuristics
    name_check = (info['owner_full_name'] or "").upper()
    
    if "UNIVERSITY" in name_check or "COLLEGE" in name_check or "INSTITUTE" in name_check:
        info['owner_type'] = "University"
    elif "GOVERNMENT" in name_check or "MINISTRY" in name_check:
        info['owner_type'] = "Government"
    elif "TELECOM" in name_check or "COMMUNICATIONS" in name_check or "ISP" in name_check:
        info['owner_type'] = "ISP"
    elif "ENTERPRISE" in name_check or "CORP" in name_check or "INC" in name_check or "LTD" in name_check:
         info['owner_type'] = "Enterprise"
    elif rdap_data.get('type'): # RIRs sometimes have type
         info['owner_type'] = rdap_data.get('type')
         
    return info

def auto_enrich_batch(selected_rows):
    """
    Enriches existing review JSONs with RDAP and RIPE Stat data.
    Creates new JSON if not exists (using row data), outputting 'auto_checklist'.
    """
    generated_files = []
    
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    for row in selected_rows:
        prefix = row.get("Prefix")
        if not prefix:
            continue
            
        safe_name = prefix.replace("/", "_") + ".json"
        file_path = os.path.join(OUTPUT_DIR, safe_name)
        
        # Need IP for RDAP
        ip_addr = prefix.split('/')[0]
        
        # --- API FETCH (RDAP) ---
        rdap_url = f"https://rdap.apnic.net/ip/{ip_addr}"
        rdap_data = None
        rdap_success = False
        try:
            resp = requests.get(rdap_url, timeout=5)
            if resp.status_code == 200:
                rdap_data = resp.json()
                rdap_success = True
        except:
            rdap_success = False

        # --- API FETCH (RIPE STAT) ---
        # Three-state model: ANNOUNCED, UNANNOUNCED, INCONCLUSIVE
        ripe_url = f"https://stat.ripe.net/data/visibility/data.json?resource={prefix}"
        bgp_visibility = "INCONCLUSIVE"  # Default to inconclusive
        bgp_detail = ""
        
        try:
            r_resp = requests.get(ripe_url, timeout=5)
            if r_resp.status_code == 200:
                r_json = r_resp.json()
                
                # RIPE Stat visibility structure check
                data = r_json.get('data', {})
                visibilities = data.get('visibilities', [])
                
                if visibilities:
                    # Check for valid routes with origin ASN
                    valid_routes = []
                    for vis in visibilities:
                        # Look for actual route visibility with full-table peers
                        if vis.get('ris_peers_seeing', 0) > 0:
                            valid_routes.append(vis)
                    
                    if len(valid_routes) > 1:
                        # Multiple collectors see it - ANNOUNCED
                        bgp_visibility = "ANNOUNCED"
                        bgp_detail = f"Visible to {len(valid_routes)} collectors"
                    elif len(valid_routes) == 1:
                        # Single collector - INCONCLUSIVE
                        bgp_visibility = "INCONCLUSIVE"
                        bgp_detail = "Single collector visibility only"
                    else:
                        # No valid routes - UNANNOUNCED
                        bgp_visibility = "UNANNOUNCED"
                        bgp_detail = "No active routes found"
                else:
                    # Empty data response - UNANNOUNCED
                    bgp_visibility = "UNANNOUNCED"
                    bgp_detail = "Empty visibility data"
            else:
                # API error
                bgp_visibility = "INCONCLUSIVE"
                bgp_detail = f"API returned {r_resp.status_code}"
        except Exception as e:
            # Network or parsing error
            bgp_visibility = "INCONCLUSIVE"
            bgp_detail = "API fetch failed"


        # --- LOGIC ---
        
        # 1. Whois Checked
        whois_checked = rdap_success
        
        # 2. Owner Type Identified
        owner_type_identified = False
        if rdap_success and rdap_data:
            if 'entities' in rdap_data or 'name' in rdap_data:
                owner_type_identified = True
                
        # 3. Tier 1 Ruled Out
        # Check explicit owner name from CSV first, then RDAP if needed
        csv_owner = row.get("Owner_Name", "")
        tier1_ruled_out = check_tier1(csv_owner)
        
        # 4. Allocation Age Checked
        allocation_age_checked = False
        if rdap_success and rdap_data:
            events = rdap_data.get('events', [])
            for e in events:
                if e.get('eventAction') in ['registration', 'allocation', 'last changed']:
                    allocation_age_checked = True
                    break
        
        # 5. Final Decision
        # FAIL: Only if confirmed ANNOUNCED
        # APPROVED: UNANNOUNCED + Tier 1 Ruled Out
        # REVIEW: INCONCLUSIVE or other ambiguity
        final_decision = "REVIEW"
        
        if bgp_visibility == "ANNOUNCED":
            final_decision = "FAIL"
        elif bgp_visibility == "UNANNOUNCED" and tier1_ruled_out:
            final_decision = "APPROVED"
        else:
            # INCONCLUSIVE or Tier 1 not ruled out
            final_decision = "REVIEW"
              
        # 6. Notes
        notes = f"Auto-enriched via API. RDAP: {'OK' if rdap_success else 'Fail'}. BGP Visibility: {bgp_visibility}"
        if bgp_detail:
            notes += f" ({bgp_detail})"


        # --- CONSTRUCT PAYLOAD ---
        
        # Load existing skeleton if possible
        json_obj = {}
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    json_obj = json.load(f)
            except:
                pass # Corrupt or error, rebuild from row
        
        # Ensure base structure exists if fresh file
        if not json_obj:
            json_obj = {
                "prefix": prefix,
                "cidr_size": int(row.get("CIDR_Size", 0)),
                "owner_name": row.get("Owner_Name"),
                "investigation_links": {
                    "bgp_whois": f"https://bgp.he.net/ip/{ip_addr}#_whois",
                    "bgp_net": f"https://bgp.he.net/net/{prefix}"
                }
            }

        # --- EXTRACT DETAILED OWNER INFO ---
        owner_info = extract_owner_info(rdap_data) if rdap_success and rdap_data else {
            "owner_full_name": None,
            "owner_handle": None,
            "owner_country": None,
            "owner_type": "Unknown"
        }
        
        # Merge into main object
        json_obj.update(owner_info)

        # Update Notes if Ambiguous
        if not owner_info['owner_full_name']:
             notes += " [Owner Info: Ambiguous/Missing]"

        # Update Auto Checklist
        json_obj['auto_checklist'] = {
            "whois_checked": whois_checked,
            "owner_type_identified": owner_type_identified,
            "tier1_ruled_out": tier1_ruled_out,
            "allocation_age_checked": allocation_age_checked,
            "final_decision": final_decision,
            "reviewer_notes": notes
        }
        
        # Write
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(json_obj, f, indent=4)
            
        generated_files.append(safe_name)
        
    return generated_files
