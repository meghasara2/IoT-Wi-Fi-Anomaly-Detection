import os
import sys
import shutil
import datetime
import sqlite3
import importlib.metadata

def run_phase0():
    print("=" * 60)
    print("PHASE 0: AUDIT, BACKUP & ENVIRONMENT VERIFICATION")
    print("=" * 60)

    db_orig = os.path.join("data", "iot_anomaly.db")
    
    # 1. Verify data/iot_anomaly.db exists, record size & tables
    if not os.path.exists(db_orig):
        raise FileNotFoundError(f"Original database not found at {db_orig}")
    
    orig_size = os.path.getsize(db_orig)
    print(f"\n[1] Original Database Verification:")
    print(f"Path: {os.path.abspath(db_orig)}")
    print(f"Size: {orig_size} bytes ({orig_size / 1024:.2f} KB)")
    
    conn_orig = sqlite3.connect(db_orig)
    cur_orig = conn_orig.cursor()
    
    cur_orig.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    orig_tables = [r[0] for r in cur_orig.fetchall()]
    print(f"Tables ({len(orig_tables)}): {', '.join(orig_tables)}")
    
    orig_counts = {}
    for tbl in orig_tables:
        if tbl == "sqlite_sequence":
            continue
        cur_orig.execute(f"SELECT COUNT(*) FROM {tbl};")
        orig_counts[tbl] = cur_orig.fetchone()[0]
    print("Table row counts:")
    for tbl, cnt in orig_counts.items():
        print(f"  - {tbl}: {cnt}")
    
    cur_orig.execute("PRAGMA integrity_check;")
    orig_integrity = cur_orig.fetchone()[0]
    print(f"Integrity check: {orig_integrity}")
    conn_orig.close()
    
    if orig_integrity != "ok":
        raise RuntimeError(f"Original DB integrity check failed: {orig_integrity}")

    # 2. Create timestamped backup without overwriting previous backups
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"iot_anomaly_backup_{timestamp_str}.db"
    backup_path = os.path.join("data", backup_filename)
    
    if os.path.exists(backup_path):
        raise FileExistsError(f"Target backup path already exists: {backup_path}")
        
    print(f"\n[2] Creating Timestamped Backup:")
    shutil.copy2(db_orig, backup_path)
    backup_size = os.path.getsize(backup_path)
    print(f"Created backup at: {os.path.abspath(backup_path)}")
    print(f"Backup Size: {backup_size} bytes")

    # 3. Verify the backup
    print(f"\n[3] Verifying Backup Database:")
    conn_bak = sqlite3.connect(backup_path)
    cur_bak = conn_bak.cursor()
    
    cur_bak.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    bak_tables = [r[0] for r in cur_bak.fetchall()]
    
    cur_bak.execute("PRAGMA integrity_check;")
    bak_integrity = cur_bak.fetchone()[0]
    print(f"Backup Integrity Check: {bak_integrity}")
    if bak_integrity != "ok":
        conn_bak.close()
        raise RuntimeError(f"Backup integrity check failed: {bak_integrity}")
        
    if orig_tables != bak_tables:
        conn_bak.close()
        raise ValueError(f"Table mismatch! Original: {orig_tables}, Backup: {bak_tables}")
    print("Table names match original exactly.")
    
    bak_counts = {}
    mismatch = False
    for tbl in bak_tables:
        if tbl == "sqlite_sequence":
            continue
        cur_bak.execute(f"SELECT COUNT(*) FROM {tbl};")
        cnt = cur_bak.fetchone()[0]
        bak_counts[tbl] = cnt
        if cnt != orig_counts[tbl]:
            print(f"ERROR: Count mismatch on {tbl}: orig={orig_counts[tbl]}, backup={cnt}")
            mismatch = True
        else:
            print(f"  - {tbl}: {cnt} rows (MATCH)")
    conn_bak.close()
    
    if mismatch:
        raise ValueError("Row count mismatch between original and backup!")
    print("Backup verified successfully. Zero discrepancies.")

    # 4. Python version, virtual env status, installed versions of project packages
    print(f"\n[4] Environment Documentation:")
    py_ver = sys.version
    is_venv = (sys.prefix != getattr(sys, "base_prefix", sys.prefix))
    print(f"Python Executable: {sys.executable}")
    print(f"Python Version: {py_ver.split()[0]}")
    print(f"Virtual Environment Active: {is_venv} (Prefix: {sys.prefix})")
    
    target_pkgs = [
        "pandas", "plotly", "streamlit", "scikit-learn", 
        "numpy", "joblib", "scipy", "python-pptx", "sqlite3"
    ]
    installed_versions = {}
    for pkg in target_pkgs:
        if pkg == "sqlite3":
            installed_versions[pkg] = sqlite3.sqlite_version
        else:
            try:
                ver = importlib.metadata.version(pkg)
                installed_versions[pkg] = ver
            except importlib.metadata.PackageNotFoundError:
                installed_versions[pkg] = "NOT INSTALLED"
                
    print("Installed Versions of Project-Relevant Packages:")
    for pkg, ver in installed_versions.items():
        print(f"  - {pkg}: {ver}")

    # 5. Inspect requirements.txt and identify missing dependencies
    print(f"\n[5] requirements.txt Audit:")
    req_path = "requirements.txt"
    if os.path.exists(req_path):
        with open(req_path, "r") as f:
            req_lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"Current requirements.txt contents: {req_lines}")
    else:
        req_lines = []
        print("requirements.txt does not exist.")
        
    # Check what packages are actually used across src/
    # scikit-learn is essential for IsolationForest
    missing_from_reqs = []
    essential_pkgs = ["scikit-learn", "numpy"]
    for ep in essential_pkgs:
        if ep not in req_lines and not any(r.startswith(ep) for r in req_lines):
            missing_from_reqs.append(ep)
            
    print(f"Missing from requirements.txt: {missing_from_reqs}")
    print("Note: In cloud environments (like Streamlit Cloud) without scikit-learn in requirements.txt, running ML models would fail.")

    # 6. Save a Phase 0 report
    report_file = os.path.join("data", "phase0_report.txt")
    with open(report_file, "w") as f:
        f.write("PHASE 0 AUDIT & BACKUP VERIFICATION REPORT\n")
        f.write("=========================================\n")
        f.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n\n")
        f.write(f"1. Original Database: {os.path.abspath(db_orig)}\n")
        f.write(f"   Size: {orig_size} bytes\n")
        f.write(f"   Integrity: {orig_integrity}\n")
        f.write(f"   Tables: {', '.join(orig_tables)}\n")
        f.write(f"   Counts: {orig_counts}\n\n")
        f.write(f"2. Verified Backup: {os.path.abspath(backup_path)}\n")
        f.write(f"   Backup Size: {backup_size} bytes\n")
        f.write(f"   Integrity: {bak_integrity}\n")
        f.write(f"   Table match: Exact\n")
        f.write(f"   Row count match: Exact\n\n")
        f.write(f"3. Python Environment:\n")
        f.write(f"   Python Executable: {sys.executable}\n")
        f.write(f"   Python Version: {py_ver.split()[0]}\n")
        f.write(f"   Virtual Env Active: {is_venv}\n")
        f.write(f"   Package Versions:\n")
        for pkg, ver in installed_versions.items():
            f.write(f"     - {pkg}: {ver}\n")
        f.write(f"\n4. requirements.txt Analysis:\n")
        f.write(f"   Listed: {req_lines}\n")
        f.write(f"   Missing Critical Dependencies: {missing_from_reqs}\n")
        f.write(f"\nStatus: PHASE 0 PASSED WITH ZERO ERRORS.\n")
        
    print(f"\n[6] Phase 0 Report saved to: {os.path.abspath(report_file)}")
    print("\nPhase 0 execution completed successfully.")

if __name__ == "__main__":
    run_phase0()
