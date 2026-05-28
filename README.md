# Concave

Concave is a concolic execution engine for EVM bytecode, built on top of caripy 
and taken inspiration from [angr](https://github.com/angr/angr), though we do not aim to neither support all features, nor assume any prior knowledge to be able to use it. 

The project is under development, has many bugs, but already has some basic functionality. 


# [First Example](example1.py)
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

It steps through the execution, not much symbolic yet, but already something!


# [Second Example](example2.py)

```python
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
```
Run
```bash
python example2.py > trace2.log
```

Now we can get branching at the JUMPI instruction: based on the symbolic expression we either take or skip the jump 


```
--------------------------------------------------
[Step 0016] PC: 0000001d | JUMPI | stack_size: 3
  Ours: ['<BV256 LShR(input_data_0_11040[11039:10784], 0xe0)>', '<BV256 if 0x8da5cb5b > LShR(input_data_0_11040[11039:10784], 0xe0) then 0x1 else 0x0>', '0x8a']
  Refs: ['0x1a1da075', '0x1', '0x8a']
  >>> STACK MISMATCH DETECTED! <<<
--------------------------------------------------
>>>>>>>>>>> Forking at JUMPI with symbolic condition: <BV256 if 0x8da5cb5b > LShR(input_data_0_11040[11039:10784], 0xe0) then 0x1 else 0x0>
Active states: 2
Finished states: 0

--------------------------------------------------
[Step 0017] PC: 0000008a | JUMPDEST | stack_size: 1
  Ours: ['<BV256 LShR(input_data_0_11040[11039:10784], 0xe0)>']
  Refs: ['0x1a1da075']
  >>> STACK MISMATCH DETECTED! <<<
--------------------------------------------------
--------------------------------------------------
[Step 0017] PC: 0000001e | DUP1 | stack_size: 1
  Ours: ['<BV256 LShR(input_data_0_11040[11039:10784], 0xe0)>']
  Refs: ['0x1a1da075']
  >>> STACK MISMATCH DETECTED! <<<
--------------------------------------------------
Active states: 2
Finished states: 0
```

Moreover you can see the symbolic stack content, which is the slice of the symbolicated input. 


# Batteries 
We collected a set of over 200'000 contracts which were active in between 24925000 and 25024999 blocks (100'000 blocks). The database of the contracts can be found in the releases. It should be put to the `db` folder.

```bash
cd db
wget https://github.com/polka125/Concave/releases/download/batteries/contracts_registry.db.gz
gunzip contracts_registry.db.gz
```

The schema is the following:

### Table: `contracts`

| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| **`address`** | `TEXT` | `PRIMARY KEY` | The smart contract address. Stored as a lowercase string (e.g., `"0x123...abc"`). |
| **`bytecode`**| `BLOB` | `NOT NULL` | The compiled smart contract bytecode. Stored as raw binary data  |


# TODOs: 
- [] Add gas tracking 
- [] Enable serial execution within one block 
- [] Type 3 transactions 
- [] refactor web3 access 
- [] There are dummy implementations in the Engine, double check, replace with real implementations
- [] Implement storage and instruction hooks 
- [] Improve logging system, especially step debugging 
- [] sane naming for top_level_code and top_level_data
- [] Add tests: concrete and symbolic. Concrete can be mined from the blockchain simulations, symbolic can be mined by executing symbolicaly, then binding the actual values and checking the correspondence. 


