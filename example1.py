from src.concave import Project

p = Project.from_tx_hash(
    "0x87cb859508438bdab46a9f98900cd245ee6ac4ac81dce4af467b9a2537cbeb18", 
    debug_trace="data/blocks/25169234/0.json.gz"
)

s = p.create_simgr()

p.dump("example1.json")

while len(s.active) > 0:
    s.step()
    print(f"Active states: {len(s.active)}")
    print(f"Finished states: {len(s.finished)}")
    print()


