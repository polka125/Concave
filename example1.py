from src.concave import Project

p = Project(
    thing="0x87cb859508438bdab46a9f98900cd245ee6ac4ac81dce4af467b9a2537cbeb18", 
    debug_trace="data/blocks/25169234/0.json.gz"
)


while len(p.simgr.active) > 0:
    p.simgr.step()
    print(f"Active states: {len(p.simgr.active)}")
    print(f"Finished states: {len(p.simgr.finished)}")
    print()
