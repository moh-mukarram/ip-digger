import pandas as pd
import os
import logging
from datetime import datetime

# Configuration
MASTER_CSV = "scout_master.csv"
TEMP_CSV = "scout_master.csv.tmp"
PRICE_PER_IP = 35.0

# Scoring Constants
SCORE_BGP_UNANNOUNCED = 50
SCORE_BGP_INCONCLUSIVE = 10
# ANNOUNCED is short-circuited to IGNORE

SCORE_ABUSE_UNKNOWN = 5   # -1
SCORE_ABUSE_LOW = 20      # 0-10
SCORE_ABUSE_MED = 5       # 11-50
SCORE_ABUSE_HIGH = 0      # > 50

SCORE_MCA_ACTIVE = 30
SCORE_MCA_UNKNOWN = 10
SCORE_MCA_STRUCK_OFF = -20
SCORE_MCA_LIQUIDATED = 0

# Caps
CAP_ABUSE_HIGH = 40
CAP_MCA_LIQUIDATED = 50

# Thresholds
THRESHOLD_READY = 80
THRESHOLD_REVIEW = 50

# Sentinels
SENTINEL_ABUSE_SCORE = -1
SENTINEL_MCA_UNKNOWN = 'UNKNOWN'

# BGP States
BGP_ANNOUNCED = "ANNOUNCED"
BGP_UNANNOUNCED = "UNANNOUNCED"
BGP_INCONCLUSIVE = "INCONCLUSIVE"

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def calculate_valuation(cidr_size):
    """
    Calculate valuation independent of readiness.
    Valuation = CIDR_Size * PRICE_PER_IP
    """
    try:
        size = int(cidr_size)
    except (ValueError, TypeError):
        return 0.0
    return size * PRICE_PER_IP

def calculate_score_and_status(row):
    """
    Calculate limits-aware readiness score and determine status.
    Returns: (Readiness_Score (int), Status_Label (str))
    """
    bgp = str(row.get('BGP_Visibility', '')).upper()
    
    # 1. BGP Short-Circuit
    if bgp == BGP_ANNOUNCED:
        return 0, "IGNORE"
    
    current_score = 0
    caps = []
    
    # 2. BGP Scoring
    if bgp == BGP_UNANNOUNCED:
        current_score += SCORE_BGP_UNANNOUNCED
    elif bgp == BGP_INCONCLUSIVE:
        current_score += SCORE_BGP_INCONCLUSIVE
    # Else 0 (but shouldn't happen if validated, or maybe None)

    # 3. Abuse Scoring
    try:
        abuse = int(row.get('Abuse_Score', SENTINEL_ABUSE_SCORE))
    except (ValueError, TypeError):
        abuse = SENTINEL_ABUSE_SCORE

    if abuse == -1:
        current_score += SCORE_ABUSE_UNKNOWN
    elif 0 <= abuse <= 10:
        current_score += SCORE_ABUSE_LOW
    elif 11 <= abuse <= 50:
        current_score += SCORE_ABUSE_MED
    else: # > 50
        current_score += SCORE_ABUSE_HIGH
        caps.append(CAP_ABUSE_HIGH)

    # 4. MCA Scoring
    # Normalize MCA status: handle case variance (though we control it strictly?)
    # Assuming forensics returns standard strings or we normalize here.
    mca = str(row.get('MCA_Status', SENTINEL_MCA_UNKNOWN)).strip()
    
    # Fuzzy match or exact match map
    # User specified: Active, Unknown, Struck Off, Liquidated
    # Let's uppercase for safety if needed, but strict string matching is better if controlled.
    # Forensics placeholder returns 'UNKNOWN'.
    
    mca_upper = mca.upper()
    if 'ACTIVE' in mca_upper:
        current_score += SCORE_MCA_ACTIVE
    elif 'STRUCK OFF' in mca_upper:
        current_score += SCORE_MCA_STRUCK_OFF
    elif 'LIQUIDATED' in mca_upper:
        current_score += SCORE_MCA_LIQUIDATED
        caps.append(CAP_MCA_LIQUIDATED)
    elif 'UNKNOWN' in mca_upper:
        current_score += SCORE_MCA_UNKNOWN
    else:
        # Default fallback for unmapped strings
        current_score += SCORE_MCA_UNKNOWN

    # 5. Apply Caps
    final_score = current_score
    if caps:
        min_cap = min(caps)
        if final_score > min_cap:
            final_score = min_cap
            
    # Clamp to 0-100?
    if final_score < 0: final_score = 0
    if final_score > 100: final_score = 100

    # 6. Status Determination
    if final_score >= THRESHOLD_READY:
        status = "READY"
    elif THRESHOLD_REVIEW <= final_score < THRESHOLD_READY:
        status = "REVIEW"
    else:
        status = "IGNORE"
        
    return int(final_score), status

def save_master_db(df):
    """Atomic write to master CSV."""
    logger.info(f"Saving {len(df)} rows to {MASTER_CSV}...")
    try:
        df.to_csv(TEMP_CSV, index=False)
        if os.path.exists(MASTER_CSV):
             os.replace(TEMP_CSV, MASTER_CSV)
        else:
             os.rename(TEMP_CSV, MASTER_CSV)
    except Exception as e:
        logger.error(f"Failed to save master DB: {e}")
        raise

def process_logic_cycle():
    """
    Main logic processing loop.
    Updates 'Valuation_Estimate', 'Readiness_Score', 'Status_Label'
    for rows that are 'Analyzed' (fresh from forensics) OR 'Stale' OR 'Pending' if we want to be safe.
    Actually, mostly 'Analyzed'.
    """
    if not os.path.exists(MASTER_CSV):
        logger.error(f"{MASTER_CSV} not found.")
        return

    try:
        df = pd.read_csv(MASTER_CSV)
        
        # Ensure correct dtypes for update cols
        if 'Valuation_Estimate' not in df.columns: df['Valuation_Estimate'] = None
        if 'Readiness_Score' not in df.columns: df['Readiness_Score'] = 0
        
        # Identify rows to process
        # We process 'Analyzed' rows. We could also re-process everything if needed (idempotency).
        # To be purely idempotent and fix any manual changes or re-runs, let's process ALL rows 
        # that are NOT 'Pending' (Pending means no forensics yet).
        # Actually, let's just process 'Analyzed' + any existing final states (Ready/Review/Ignore) 
        # to ensure rules update if we change logic.
        
        # Filter: Status_Label != 'Pending'
        # Or explicitly: Analyzed, Ready, Review, Ignore.
        # Let's process everything except 'Pending'.
        mask = df['Status_Label'] != 'Pending'
        
        process_indices = df[mask].index
        logger.info(f"Processing logic for {len(process_indices)} rows...")
        
        updates_count = 0
        
        for idx in process_indices:
            row = df.loc[idx]
            
            # 1. Valuation
            val = calculate_valuation(row['CIDR_Size'])
            df.at[idx, 'Valuation_Estimate'] = val
            
            # 2. Score & Status
            score, status = calculate_score_and_status(row)
            df.at[idx, 'Readiness_Score'] = score
            df.at[idx, 'Status_Label'] = status
            
            updates_count += 1
            
        if updates_count > 0:
            save_master_db(df)
            logger.info("Logic cycle complete. Master DB updated.")
        else:
            logger.info("No rows to update.")
            
    except Exception as e:
        logger.error(f"Logic cycle failed: {e}")
        raise

if __name__ == "__main__":
    process_logic_cycle()
