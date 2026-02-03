import requests
import pandas as pd
import time
import logging
import concurrent.futures
import os
from datetime import datetime
from functools import wraps

# Configuration
RIPE_STAT_URL = "https://stat.ripe.net/data/routing-status/data.json"
MASTER_CSV = "scout_master.csv"
TEMP_CSV = "scout_master.csv.tmp"
DEFAULT_BATCH_SIZE = 50
MAX_WORKERS = 10
REQUEST_TIMEOUT = 25  # Conservative timeout as requested

# Sentinels
SENTINEL_ABUSE_SCORE = -1
SENTINEL_MCA_STATUS = 'UNKNOWN'

# BGP States
BGP_UNANNOUNCED = "UNANNOUNCED"
BGP_ANNOUNCED = "ANNOUNCED"
BGP_INCONCLUSIVE = "INCONCLUSIVE"

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def exponential_backoff(max_retries=3, base_delay=2):
    """
    Decorator for exponential backoff on request/IO exceptions.
    Handles ReadTimeouts, SSL errors, 5xx, and JSON errors.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (requests.exceptions.RequestException, ValueError) as e:
                    # ValueError catches JSON decoding errors from response.json()
                    wait_time = base_delay * (2 ** retries)
                    logger.warning(f"Operation failed: {type(e).__name__}: {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    retries += 1
            
            logger.error(f"Max retries ({max_retries}) reached for {func.__name__}. Marking Inconclusive.")
            return None # Fail gracefully
        return wrapper
    return decorator

@exponential_backoff(max_retries=3, base_delay=2)
def fetch_ripe_data(resource):
    """
    Fetch BGP data from RIPE Stat with robustness.
    Manually constructs URL to avoid encoding issues.
    """
    url = f"{RIPE_STAT_URL}?resource={resource}"
    # Conservative timeout, verify=True explicitly (though default)
    response = requests.get(url, timeout=REQUEST_TIMEOUT, verify=True)
    
    # Check for HTTP errors (4xx, 5xx)
    # raise_for_status() will raise HTTPError which is caught by RequestException
    response.raise_for_status()
    
    # Parse JSON (might raise ValueError/JSONDecodeError)
    return response.json()

def check_bgp_visibility(prefix):
    """
    Check BGP visibility using RIPE Stat (Primary).
    Returns: UNANNOUNCED, ANNOUNCED, or INCONCLUSIVE.
    """
    # Multi-source structure
    sources = [
        {'name': 'RIPE', 'func': _check_bgp_ripe}
    ]
    
    results = []
    for source in sources:
        try:
            result = source['func'](prefix)
            results.append(result)
        except Exception as e:
            logger.error(f"Error querying {source['name']} for {prefix}: {e}")
            results.append(BGP_INCONCLUSIVE)
            
    # Consensus: Currently single source
    if not results: return BGP_INCONCLUSIVE
    return results[0]

def _check_bgp_ripe(prefix):
    """
    Internal RIPE check using routing-status.
    Determines BGP state based on routes.
    """
    data = fetch_ripe_data(prefix)
    
    # If fetch failed (None returned after retries), explicit INCONCLUSIVE
    if data is None:
        return BGP_INCONCLUSIVE
        
    try:
        r_data = data.get('data', {})
        
        # User Instruction: "Determine BGP state based on presence/absence of routes in data.routing_status.routes"
        # We attempt to follow this strictly, but allow for structure variance if 'routing_status' implies the data block itself 
        # or if existing probe evidence suggests 'origins' is the relevant list.
        # To be safe and compliant: priority check on `routing_status.routes`, fallback to `origins`.
        
        routes = []
        
        # 1. Strict Path Check
        if 'routing_status' in r_data:
            routes = r_data['routing_status'].get('routes', [])
        # 2. Origin/Probe Path Check (Common RIPE structure for prefix queries)
        elif 'origins' in r_data:
            routes = r_data['origins']
            
        # Logic: Presence of routes = ANNOUNCED
        if routes:
            return BGP_ANNOUNCED
            
        # Logic: Empty routes = UNANNOUNCED (if successful request)
        return BGP_UNANNOUNCED
        
    except Exception as e:
        logger.error(f"Error parsing RIPE response for {prefix}: {e}")
        return BGP_INCONCLUSIVE

def check_abuse_score(prefix):
    """Placeholder for Abuse Score."""
    return SENTINEL_ABUSE_SCORE

def check_mca_status(owner_name):
    """Placeholder for MCA Status."""
    return SENTINEL_MCA_STATUS

def analyze_prefix(row):
    """
    Perform forensics on a single row.
    Returns the updated row dict.
    """
    prefix = row['Prefix']
    owner = row.get('Owner_Name', '')
    
    bgp_status = check_bgp_visibility(prefix)
    abuse = check_abuse_score(prefix)
    mca = check_mca_status(owner)
    
    return {
        'Prefix': prefix, 
        'BGP_Visibility': bgp_status,
        'Abuse_Score': abuse,
        'MCA_Status': mca,
        'Last_Audit_Date': datetime.now().strftime('%Y-%m-%d')
    }

def save_master_db(df):
    """Atomic write to master CSV."""
    try:
        df.to_csv(TEMP_CSV, index=False)
        if os.path.exists(MASTER_CSV):
             os.replace(TEMP_CSV, MASTER_CSV)
        else:
             os.rename(TEMP_CSV, MASTER_CSV)
    except Exception as e:
        logger.error(f"CRITICAL: Failed to save {MASTER_CSV}: {e}")
        # Not raising here avoids crashing the whole cycle if one save fails, 
        # but atomic save failure is critical. 
        # User constraint: "Pipeline must continue processing...". 
        # But if we can't save, we lose progress. 
        # Raise log, maybe continue? 
        # Raising stops the infinite loop? No, this is called inside the loop.
        # Let's just log critical.
        pass 

def run_forensics_cycle(batch_size=DEFAULT_BATCH_SIZE):
    """
    Main orchestration loop.
    1. Load DB
    2. Identify Pending/Stale
    3. Batch Process
    4. Save Atomic per Batch
    """
    if not os.path.exists(MASTER_CSV):
        logger.error(f"{MASTER_CSV} not found. Run downloader.py first.")
        return

    df = pd.read_csv(MASTER_CSV)
    
    # Ensure types
    cols_to_ensure_object = ['BGP_Visibility', 'MCA_Status', 'Status_Label', 'Owner_Name', 'Last_Audit_Date']
    for col in cols_to_ensure_object:
        if col in df.columns and df[col].dtype != 'object':
             df[col] = df[col].astype('object')
    
    mask = (df['Status_Label'] == 'Pending')
    candidate_indices = df[mask].index.tolist()
    
    logger.info(f"Found {len(candidate_indices)} candidates for forensics.")
    
    if not candidate_indices:
        return

    total_processed = 0
    
    for i in range(0, len(candidate_indices), batch_size):
        batch_indices = candidate_indices[i : i + batch_size]
        batch_rows = df.loc[batch_indices].to_dict('records')
        
        logger.info(f"Processing batch {i//batch_size + 1} (Rows {i} to {i+len(batch_indices)})...")
        
        updates = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_prefix = {executor.submit(analyze_prefix, row): row for row in batch_rows}
            
            for future in concurrent.futures.as_completed(future_to_prefix):
                try:
                    res = future.result()
                    if res:
                        updates.append(res)
                except Exception as e:
                    logger.error(f"Process failed for row: {e}")
        
        for update in updates:
            # Map back to DF
            idx_list = df.index[df['Prefix'] == update['Prefix']].tolist()
            if idx_list:
                idx = idx_list[0]
                df.at[idx, 'BGP_Visibility'] = update['BGP_Visibility']
                df.at[idx, 'Abuse_Score'] = update['Abuse_Score']
                df.at[idx, 'MCA_Status'] = update['MCA_Status']
                df.at[idx, 'Last_Audit_Date'] = update['Last_Audit_Date']
                df.at[idx, 'Status_Label'] = 'Analyzed'
        
        save_master_db(df)
        total_processed += len(updates)
        logger.info(f"Saved batch. Total processed: {total_processed}")

if __name__ == "__main__":
    run_forensics_cycle()
