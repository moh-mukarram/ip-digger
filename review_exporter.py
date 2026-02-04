import os
import json
import datetime

OUTPUT_DIR = "output/review_queue/"

def export_review_batch(selected_rows):
    """
    Exports a list of row dictionaries to individual JSON files (Skeleton Only).
    Does NOT include any checklist fields.
    """
    # Ensure output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    generated_files = []
    
    for row in selected_rows:
        prefix = row.get("Prefix")
        if not prefix:
            continue
            
        # Prepare content
        obj = {
            "prefix": prefix,
            "cidr_size": int(row.get("CIDR_Size", 0)),
            "owner_name": row.get("Owner_Name"),
            "country": row.get("Country", "Unknown"), # Using default as key might differ
            "bgp_visibility": row.get("BGP_Visibility"),
            "abuse_score": row.get("Abuse_Score"),
            "mca_status": row.get("MCA_Status"),
            "valuation_estimate": float(row.get("Valuation_Estimate", 0.0)),
            "readiness_score": float(row.get("Readiness_Score", 0.0)),
            "status_label": row.get("Status_Label"),
            "last_audit_date": row.get("Last_Audit_Date"),
            "investigation_links": {
                "bgp_whois": f"https://bgp.he.net/ip/{prefix.split('/')[0]}#_whois",
                "bgp_net": f"https://bgp.he.net/net/{prefix}"
            }
        }
        
        # Filename: 1.2.3.0_24.json
        safe_name = prefix.replace("/", "_") + ".json"
        file_path = os.path.join(OUTPUT_DIR, safe_name)
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=4)
            
        generated_files.append(safe_name)
        
    return generated_files
