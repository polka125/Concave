from src.concave import Project
import claripy

p = Project(
    thing="0x87cb859508438bdab46a9f98900cd245ee6ac4ac81dce4af467b9a2537cbeb18", 
    debug_trace="data/blocks/25169234/0.json.gz"
)

# top_level_data stored as bytes
concrete_data = p.top_level_data

# each byte is 8 bits
symbolic_data = claripy.BVS("input_data", len(concrete_data) * 8) 

# replace the concrete data with symbolic data
p.set_top_level_data(symbolic_data)

while len(p.simgr.active) > 0:
    p.simgr.step()
    print(f"Active states: {len(p.simgr.active)}")
    print(f"Finished states: {len(p.simgr.finished)}")
    print()
