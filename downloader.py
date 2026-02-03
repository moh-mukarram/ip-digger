import requests
import pandas as pd
import math
import os
import csv
import logging
from datetime import datetime

# Configuration
APNIC_URL = "http://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest"
MASTER_CSV = "scout_master.csv"
TEMP_CSV = "scout_master.csv.tmp"
DEFAULT_COLUMNS = [
    "Prefix", "CIDR_Size", "Owner_Name", "BGP_Visibility", 
    "Abuse_Score", "MCA_Status", "Valuation_Estimate", 
    "Readiness_Score", "Status_Label", "Last_Audit_Date"
]

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_power_of_two(n):
    """Check if n is a power of two."""
    return (n != 0) and (n & (n - 1) == 0)

def count_to_cidr_mask(count):
    """Convert IP count to CIDR mask bits."""
    return 32 - int(math.log2(count))

def fetch_apnic_data(url):
    """Fetch data from APNIC URL."""
    logger.info(f"Fetching APNIC data from {url}...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.error(f"Failed to fetch APNIC data: {e}")
        raise

def parse_apnic_data(data, target_cc=None):
    """Parse APNIC data and return list of new rows."""
    logger.info("Parsing APNIC data...")
    new_entries = []
    
    # Skip summary lines (lines starting with 2 or 2.3) and comments
    lines = data.splitlines()
    for line in lines:
        if line.startswith('#') or not line.strip():
            continue
            
        parts = line.split('|')
        if len(parts) < 7:
            continue
            
        # registry|cc|type|start|value|date|status
        registry, cc, type_, start, value, date, status = parts[:7]
        
        # Filter: IPv4 only
        if type_ != 'ipv4':
            continue
            
        # Filter by Country if specified
        if target_cc and cc != target_cc:
            continue
            
        try:
            value = int(value)
        except ValueError:
            continue
            
        # Constraint: Value must be a power of two
        if not is_power_of_two(value):
            continue
            
        # Calculate CIDR
        mask = count_to_cidr_mask(value)
        prefix = f"{start}/{mask}"
        
        new_entries.append({
            "Prefix": prefix,
            "CIDR_Size": value,
            "Owner_Name": f"{cc}-{status}", # Placeholder
            "BGP_Visibility": None,
            "Abuse_Score": None,
            "MCA_Status": None,
            "Valuation_Estimate": None,
            "Readiness_Score": 0,
            "Status_Label": "Pending",
            "Last_Audit_Date": None
        })
        
    return new_entries

def load_master_db():
    """Load existing master CSV or create empty DataFrame."""
    if os.path.exists(MASTER_CSV):
        try:
            return pd.read_csv(MASTER_CSV)
        except Exception as e:
            logger.error(f"Error loading {MASTER_CSV}: {e}")
            # If corrupt, we might need a backup, but for now allow fail
            raise
    else:
        return pd.DataFrame(columns=DEFAULT_COLUMNS)

def save_master_db(df):
    """Atomic write to master CSV."""
    logger.info(f"Saving {len(df)} rows to {MASTER_CSV}...")
    try:
        df.to_csv(TEMP_CSV, index=False)
        # Atomic rename (on Windows convert to atomic replace if needed, but os.replace is atomic on POSIX and often Windows Python 3.3+)
        if os.path.exists(MASTER_CSV):
             os.replace(TEMP_CSV, MASTER_CSV)
        else:
             os.rename(TEMP_CSV, MASTER_CSV)
    except Exception as e:
        logger.error(f"Failed to save master DB: {e}")
        raise

def run_ingestion(target_cc=None):
    """Main execution entry point."""
    try:
        # 1. Fetch
        raw_data = fetch_apnic_data(APNIC_URL)
        
        # 2. Parse (Candidates)
        candidates = parse_apnic_data(raw_data, target_cc)
        if not candidates:
            logger.warning("No candidates found.")
            return {"new": 0, "stale": 0, "total": 0}
            
        candidates_df = pd.DataFrame(candidates)
        
        # 3. Load Master
        master_df = load_master_db()
        existing_prefixes = set(master_df['Prefix'].unique()) if not master_df.empty else set()
        
        # 4. Delta Diff
        # Identify New
        new_df = candidates_df[~candidates_df['Prefix'].isin(existing_prefixes)]
        
        new_count = len(new_df)
        stale_count = 0 # Placeholder: Stale logic would check Last_Audit_Date on existing
        
        if not new_df.empty:
            logger.info(f"Found {new_count} new prefixes.")
            # Append new
            updated_master = pd.concat([master_df, new_df], ignore_index=True)
        else:
            updated_master = master_df
            
        # 5. Persist
        if not new_df.empty:
            save_master_db(updated_master)
        
        total_count = len(updated_master)
        
        return {
            "new": new_count,
            "stale": stale_count,
            "total": total_count
        }

    except Exception as e:
        logger.error(f"Ingestion failed: {e}")
        raise

if __name__ == "__main__":
    # Example usage (can be customized via args in future)
    # IN for India as an example or None for all
    summary = run_ingestion(target_cc=None) 
    print(summary)
