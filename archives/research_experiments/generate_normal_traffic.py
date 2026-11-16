import pandas as pd
import numpy as np
from pathlib import Path
import random

def simulate_node_traffic(node_id, node_type, min_iat, max_iat, duration_sec, packet_size_range=(60, 100), bursty=False):
    """
    Simulates traffic for a single IoT node over a given duration.
    """
    records = []
    current_time = 0.0
    
    while current_time < duration_sec:
        # Generate IAT with random variation uniformly between min and max
        iat = random.uniform(min_iat, max_iat)
        
        # Occasional legitimate burst for motion sensors (e.g. 5% chance of a burst)
        if bursty and random.random() < 0.05:
            # Simulate a quick burst of 2-4 packets very close together
            burst_count = random.randint(2, 4)
            for _ in range(burst_count):
                burst_iat = random.uniform(0.05, 0.2)
                current_time += burst_iat
                records.append({
                    "Node_ID": node_id,
                    "Node_Type": node_type,
                    "Timestamp": current_time,
                    "IAT": burst_iat,
                    "Packet_Size": int(random.uniform(packet_size_range[0], packet_size_range[1]))
                })
        else:
            current_time += iat
            records.append({
                "Node_ID": node_id,
                "Node_Type": node_type,
                "Timestamp": current_time,
                "IAT": iat,
                "Packet_Size": int(random.uniform(packet_size_range[0], packet_size_range[1]))
            })
            
    return records

def main():
    # Set a fixed random seed for reproducibility
    random.seed(42)
    np.random.seed(42)
    
    # Simulate 300 seconds (5 minutes) of traffic to create a meaningful baseline
    SIMULATION_DURATION = 1800 
    
    all_traffic = []
    
    # Node 1: Temperature Sensor (2-3 seconds)
    all_traffic.extend(simulate_node_traffic("Node_1", "Temperature Sensor", 2.0, 3.0, SIMULATION_DURATION))
    
    # Node 2: Smart Light (1-2 seconds)
    all_traffic.extend(simulate_node_traffic("Node_2", "Smart Light", 1.0, 2.0, SIMULATION_DURATION))
    
    # Node 3: Smart Plug (0.8-1.5 seconds)
    all_traffic.extend(simulate_node_traffic("Node_3", "Smart Plug", 0.8, 1.5, SIMULATION_DURATION))
    
    # Node 4: Motion Sensor (3-6 seconds, with occasional legitimate bursts)
    all_traffic.extend(simulate_node_traffic("Node_4", "Motion Sensor", 3.0, 6.0, SIMULATION_DURATION, bursty=True))
    
    # Node 5: Camera-like Traffic Generator (0.2-0.5 seconds)
    # Using larger packet sizes just to add realistic variety to a camera profile
    all_traffic.extend(simulate_node_traffic("Node_5", "Camera-like Traffic Generator", 0.2, 0.5, SIMULATION_DURATION, packet_size_range=(1000, 1500)))
    
    # Create a DataFrame and sort by Timestamp to simulate a merged network capture
    df = pd.DataFrame(all_traffic)
    df = df.sort_values(by="Timestamp").reset_index(drop=True)
    
    # Save the generated traffic
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = processed_dir / "normal_5node_traffic.csv"
    df.to_csv(output_path, index=False)
    
    # Print requested statistics
    print(f"--- Traffic Generation Complete ---")
    print(f"Output File: {output_path}")
    print(f"Total rows generated: {len(df)}\n")
    
    print("Rows per node:")
    print(df["Node_ID"].value_counts().to_string())
    print("\n")
    
    print("First 10 rows of generated traffic:")
    print(df.head(10).to_string())

if __name__ == "__main__":
    main()
