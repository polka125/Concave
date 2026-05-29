import os
import gzip
import json
import tqdm
from collections import defaultdict

# Configuration
TRACES_DIR = "hide/traces"
OUTPUT_FILE = "testdata/concrete.json"
LIMIT_PER_OPCODE = 50

def main():
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Get all .json.gz files
    files = [f for f in os.listdir(TRACES_DIR) if f.endswith(".json.gz")]
    
    # Dictionary to store the results: { opcode: [list of examples] }
    test_data = defaultdict(list)

    for filename in tqdm.tqdm(files, desc="Processing files"):
        # Parse block number and tx id from filename (e.g., 25024990_0.json.gz)
        base_name = filename.replace(".json.gz", "")
        try:
            block_number, tx_id = base_name.split("_")
        except ValueError:
            print(f"Skipping file with unexpected name format: {filename}")
            continue

        filepath = os.path.join(TRACES_DIR, filename)
        
        with gzip.open(filepath, "rt") as f:
            # Read all lines to easily access the next line
            # (If files are extremely large, you can use a sliding window iterator instead)
            lines = f.readlines()
            
            for i in range(len(lines)):
                current_line_str = lines[i].strip()
                if not current_line_str:
                    continue
                
                next_line_str = lines[i+1].strip() if i + 1 < len(lines) else None
                
                try:
                    current_json = json.loads(current_line_str)
                    opName = current_json.get("opName")
                    
                    if opName and len(test_data[opName]) < LIMIT_PER_OPCODE:
                        # Parse the next line if it exists
                        next_json = None
                        if next_line_str:
                            next_json = json.loads(next_line_str)
                            
                        # Save the required data
                        test_data[opName].append({
                            "block_number": int(block_number),
                            "tx_id": int(tx_id),
                            "current_line": current_json,
                            "next_line": next_json
                        })
                        
                except json.JSONDecodeError:
                    pass

    # Save the collected test data to the target file
    with open(OUTPUT_FILE, "w") as out_f:
        json.dump(test_data, out_f, indent=2)
        
    print(f"\nSuccessfully saved test data to {OUTPUT_FILE}")
    print("Collected counts per opcode:")
    for opcode, items in sorted(test_data.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {opcode}: {len(items)}")

if __name__ == "__main__":
    main()