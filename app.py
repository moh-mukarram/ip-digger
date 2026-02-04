import streamlit as st
import pandas as pd
import os
import downloader
import forensics
import logic
import review_exporter
import review_auto_enricher
import time
import math

# --- Configuration ---
MASTER_CSV = "scout_master.csv"
st.set_page_config(page_title="IP-DIGGER Control Center", layout="wide")

# --- Session State Management ---
if 'job_running' not in st.session_state:
    st.session_state.job_running = False
if 'last_status' not in st.session_state:
    st.session_state.last_status = "Ready"

# Filter Persistence
if 'filter_status' not in st.session_state:
    st.session_state.filter_status = ['READY', 'REVIEW']
if 'filter_country' not in st.session_state:
    st.session_state.filter_country = ""
if 'filter_score' not in st.session_state:
    st.session_state.filter_score = (0, 100)

# Sort Persistence (Multi-Column)
if 'sort_col_1' not in st.session_state:
    st.session_state.sort_col_1 = "Readiness_Score"
if 'sort_asc_1' not in st.session_state:
    st.session_state.sort_asc_1 = False # Default Descending
if 'sort_col_2' not in st.session_state:
    st.session_state.sort_col_2 = "Valuation_Estimate"
if 'sort_asc_2' not in st.session_state:
    st.session_state.sort_asc_2 = False

def run_job_wrapper(job_func, *args, **kwargs):
    """
    Wrapper to handle job execution with UI locking.
    """
    st.session_state.job_running = True
    try:
        with st.spinner("Processing..."):
            result = job_func(*args, **kwargs)
            st.session_state.last_status = f"Success: {result if result else 'Completed'}"
            st.success("Job Completed Successfully")
    except Exception as e:
        st.session_state.last_status = f"Error: {str(e)}"
        st.error(f"Job Failed: {e}")
    finally:
        st.session_state.job_running = False

# --- Sidebar Controls ---
st.sidebar.title("Operator Controls")

target_cc = st.sidebar.text_input("Target CC (e.g., IN, US)", value="IN").upper()
if not target_cc: target_cc = None

# UI Locking
is_locked = st.session_state.job_running

if st.sidebar.button("Run 1: Ingestion (Downloader)", disabled=is_locked):
    run_job_wrapper(downloader.run_ingestion, target_cc=target_cc)
    st.rerun()

if st.sidebar.button("Run 2: Forensics (Status Check)", disabled=is_locked):
    # Explicit batch size
    run_job_wrapper(forensics.run_forensics_cycle, batch_size=50)
    st.rerun()

if st.sidebar.button("Run 3: Logic (Scoring)", disabled=is_locked):
    run_job_wrapper(logic.process_logic_cycle)
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(f"**System Status**: {st.session_state.last_status}")
if is_locked:
    st.sidebar.warning("Job is running...")

# --- Main Dashboard ---
st.title("IP-DIGGER: IPv4 Scout Engine")

if os.path.exists(MASTER_CSV):
    try:
        df = pd.read_csv(MASTER_CSV)
        
        # Ensure Numeric for Stats
        df['Valuation_Estimate'] = pd.to_numeric(df['Valuation_Estimate'], errors='coerce').fillna(0)
        df['CIDR_Size'] = pd.to_numeric(df['CIDR_Size'], errors='coerce').fillna(0)
        # Ensure Score is numeric
        df['Readiness_Score'] = pd.to_numeric(df['Readiness_Score'], errors='coerce').fillna(0)
        
        # --- KPIs ---
        kpi_mask = df['Status_Label'].isin(['READY', 'REVIEW'])
        
        total_val = df.loc[kpi_mask, 'Valuation_Estimate'].sum()
        ready_count = len(df[df['Status_Label'] == 'READY'])
        review_count = len(df[df['Status_Label'] == 'REVIEW'])
        total_ips = len(df)
        
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Pipeline Value (Ready/Review)", f"${total_val:,.0f}")
        k2.metric("Ready Blocks", ready_count)
        k3.metric("Review Blocks", review_count)
        k4.metric("Total Tracked Blocks", total_ips)
        
        # --- Tabs ---
        tab1, tab2 = st.tabs(["Data Explorer", "Outreach Generator"])
        
        with tab1:
            st.subheader("Scout Master Database")
            
            # Filters Row
            c1, c2, c3 = st.columns(3)
            with c1:
                # Status Filter - Persisted
                all_statuses = sorted(df['Status_Label'].unique().astype(str))
                st.multiselect(
                    "Status Label", 
                    all_statuses, 
                    key="filter_status"
                )
            with c2:
                # Country Filter (Optional) - Persisted
                st.text_input("Country (Owner/Code)", key="filter_country")
            with c3:
                # Score Filter (Numeric) - Persisted
                st.slider("Readiness Score", 0, 100, key="filter_score")
            
            # --- Sorting Controls (Multi-Column) ---
            st.markdown("##### Sorting")
            sort_opts = ["Readiness_Score", "Valuation_Estimate", "CIDR_Size", "Last_Audit_Date", "Prefix"]
            
            r1_c1, r1_c2, r2_c1, r2_c2 = st.columns([3, 1, 3, 1])
            with r1_c1:
                st.selectbox("Primary Sort", sort_opts, key="sort_col_1")
            with r1_c2:
                st.checkbox("Ascending (1)", key="sort_asc_1")
            
            with r2_c1:
                st.selectbox("Secondary Sort", sort_opts, key="sort_col_2")
            with r2_c2:
                st.checkbox("Ascending (2)", key="sort_asc_2")
            
            # Apply Logic
            view_df = df.copy()
            status_sel = st.session_state.filter_status
            country_sel = st.session_state.filter_country
            min_s, max_s = st.session_state.filter_score
            
            # 1. Filter
            if status_sel:
                view_df = view_df[view_df['Status_Label'].isin(status_sel)]
            if country_sel:
                view_df = view_df[view_df['Owner_Name'].str.contains(country_sel, case=False, na=False)]
            
            view_df = view_df[
                (view_df['Readiness_Score'] >= min_s) & 
                (view_df['Readiness_Score'] <= max_s)
            ]
            
            # 2. Sort (Multi-Column)
            # Retrieve persistence
            sc1 = st.session_state.sort_col_1
            asc1 = st.session_state.sort_asc_1
            sc2 = st.session_state.sort_col_2
            asc2 = st.session_state.sort_asc_2
            
            # Verify columns exist
            valid_cols = view_df.columns
            sort_keys = []
            sort_dirs = []
            
            if sc1 in valid_cols:
                sort_keys.append(sc1)
                sort_dirs.append(asc1)
            
            if sc2 in valid_cols and sc2 != sc1: # Avoid duplicate sorting
                sort_keys.append(sc2)
                sort_dirs.append(asc2)
                
            if sort_keys:
                 view_df = view_df.sort_values(by=sort_keys, ascending=sort_dirs)
            
            # --- Add BGP WHOIS Link ---
            # Generate URL: https://bgp.he.net/ip/<IP>#_whois
            if 'Prefix' in view_df.columns:
                view_df['whois_url'] = view_df['Prefix'].apply(
                    lambda x: f"https://bgp.he.net/ip/{x.split('/')[0]}#_whois" if isinstance(x, str) else None
                )
            
            # --- Selection UI ---
            view_df.insert(0, "Select", False)

            edited_df = st.data_editor(
                view_df, 
                width="stretch",
                column_config={
                    "whois_url": st.column_config.LinkColumn(
                        "BGP WHOIS",
                        display_text="WHOIS"
                    ),
                    "Select": st.column_config.CheckboxColumn(
                        "Select",
                        help="Select for Manual Review Export",
                        default=False,
                    )
                },
                disabled=[c for c in view_df.columns if c != "Select"],
                hide_index=True
            )
            st.caption(f"Showing {len(view_df)} rows")
            
            # --- Export Action ---
            st.markdown("### Actions")
            c1, c2 = st.columns(2)
            
            with c1:
                if st.button("Generate Review JSON (max 5)"):
                    selected_rows = edited_df[edited_df['Select'] == True]
                    count = len(selected_rows)
                    
                    if count == 0:
                        st.warning("No rows selected.")
                    elif count > 5:
                        st.error(f"Selection Limit Exceeded. You selected {count} rows (Max: 5).")
                    else:
                        rows_data = selected_rows.to_dict('records')
                        try:
                            files = review_exporter.export_review_batch(rows_data)
                            st.success(f"Generated {len(files)} skeleton files.")
                        except Exception as e:
                            st.error(f"Export failed: {e}")
                            
            with c2:
                if st.button("Auto Review Selected Prefixes (max 5)"):
                    selected_rows = edited_df[edited_df['Select'] == True]
                    count = len(selected_rows)
                    
                    if count == 0:
                        st.warning("No rows selected.")
                    elif count > 5:
                        st.error(f"Selection Limit Exceeded. You selected {count} rows (Max: 5).")
                    else:
                        rows_data = selected_rows.to_dict('records')
                        try:
                            # Calls the auto enricher
                            files = review_auto_enricher.auto_enrich_batch(rows_data)
                            st.success(f"Enriched {len(files)} files with API data.")
                        except Exception as e:
                            st.error(f"Enrichment failed: {e}")
            
        with tab2:
            st.subheader("Teaser Generator")
            # Only READY rows
            ready_rows = df[df['Status_Label'] == 'READY']
            
            if not ready_rows.empty:
                # Select Prefix
                prefix_opts = ready_rows['Prefix'].unique()
                sel_prefix = st.selectbox("Select Ready Prefix", prefix_opts)
                
                if sel_prefix:
                    # Get Row Data
                    row = ready_rows[ready_rows['Prefix'] == sel_prefix].iloc[0]
                    
                    # Prepare Interpolation Variables
                    p_prefix = row['Prefix']
                    p_size = int(row['CIDR_Size'])
                    p_val = float(row['Valuation_Estimate'])
                    
                    # Calculate Mask
                    try:
                        p_mask = 32 - int(math.log2(p_size))
                    except:
                        p_mask = "??"
                    
                    teaser = f"Offering /{p_mask} block {p_prefix} ({p_size} IPs). Est. Value: ${p_val:,.2f}. Clean & Unannounced."
                    
                    st.code(teaser, language="text")
                    st.info("Copy the text above.")
            else:
                st.info("No blocks marked 'READY'.")
                
    except Exception as e:
        st.error(f"Error loading data: {e}")
else:
    st.warning("Database not found. Please run Ingestion.")
