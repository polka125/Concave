from src.concave import Project
import claripy



p = Project.from_tx_hash(
    "0x87cb859508438bdab46a9f98900cd245ee6ac4ac81dce4af467b9a2537cbeb18",
    debug_trace="data/blocks/25169234/0.json.gz"
)


concrete_data = p.top_level_data
symbolic_data = claripy.BVS("input_data", len(concrete_data) * 8) 
simgr = p.create_simgr(custom_calldata=symbolic_data)



while len(simgr.active) > 0:
    simgr.step()
    print(f"Active states: {len(simgr.active)}")
    print(f"Finished states: {len(simgr.finished)}")
    print()
