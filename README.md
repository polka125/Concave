The project is under development, and is not production ready yet. Once it is tested, this note will be updated. 

Currently, a basic stepping and symbolic emulation implemented. However, now we rely on hardcoded memory values, which we get form REVM logs. 

# First Example 
The simplest thing we can do is just step through the execution.


First, need to setup a JSON RPC `WEB3_JSON_RPC`, for example might use the public one:

```bash
export WEB3_JSON_RPC="https://ethereum-rpc.publicnode.com"
```

Then run the [example](example1.py):

```python
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

```

```
python example1.py > trace.log
```

# Concave

Concave is a concolic execution engine for EVM bytecode, built on top of caripy 
and taken inspiration from [angr](https://github.com/angr/angr), though we do not aim to neither support all features, nor assume any prior knowledge to be able to use it. 


Todo: 
- [] Add gas tracking 
- [] Enable serial execution within one block 
- [] Type 3 transactions 
- [] Enable JSON-RPC support
- [] There are dummy implementations in the Engine, double check, replace with real implementations
- [] Improve docs
- [] Implement storage and instruction hooks 
- [] Improve logging system, especially step debugging 



# Development 

The `data` folder conatains some executed blocks (we used [REVM block tracer](https://github.com/bluealloy/revm/tree/main/examples/block_traces)). The data is automatically gzipped on commit to keep the storage low (too lazy to setup lfs). Yout can unzip all with 

```
gunzip -r data/
```

It will be zipped back on commit (thanks to a pre-commit hook).