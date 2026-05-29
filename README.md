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

p = Project.from_tx_hash(
    "0x87cb859508438bdab46a9f98900cd245ee6ac4ac81dce4af467b9a2537cbeb18", 
    debug_trace="data/blocks/25169234/0.json.gz"
)
s = p.create_simgr()
while len(s.active) > 0:
    s.step()
    print(f"Active states: {len(s.active)}")
    print(f"Finished states: {len(s.finished)}")
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


# Tests

## Unit tests

### Concrete tests
For tests we use revm traces as ground truth, which split into bins based on opcodes. The pairs (pre-state, post-state) could be fround at `testdata`
the tests can be run with 
```bash
pytest tests/test.py -v
```

Currently uncovered opcodes are: 
```
===================================================== Opcode Coverage Report =====================================================
Covered opcodes (91): ADD, ADDMOD, AND, BYTE, DIV, DUP1, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8, DUP9, EQ, EXP, GT, ISZERO, LT, MOD, MUL, MULMOD, NOT, OR, POP, PUSH0, PUSH1, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16, PUSH17, PUSH18, PUSH19, PUSH2, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24, PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH3, PUSH30, PUSH31, PUSH32, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8, PUSH9, SAR, SDIV, SGT, SHL, SHR, SIGNEXTEND, SLT, SMOD, SUB, SWAP1, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8, SWAP9, XOR

Uncovered opcodes (55): ADDRESS, BALANCE, BASEFEE, BLOBBASEFEE, BLOBHASH, BLOCKHASH, CALL, CALLDATACOPY, CALLDATALOAD, CALLDATASIZE, CALLER, CALLVALUE, CHAINID, CLZ, CODECOPY, CODESIZE, COINBASE, CREATE, CREATE2, DELEGATECALL, DIFFICULTY, EXTCODECOPY, EXTCODEHASH, EXTCODESIZE, GAS, GASPRICE, INVALID, JUMP, JUMPDEST, JUMPI, KECCAK256, LOG0, LOG1, LOG2, LOG3, LOG4, MCOPY, MLOAD, MSTORE, MSTORE8, NUMBER, ORIGIN, RETURN, RETURNDATACOPY, RETURNDATASIZE, REVERT, SELFBALANCE, SELFDESTRUCT, SLOAD, SSTORE, STATICCALL, STOP, TIMESTAMP, TLOAD, TSTORE
================================================= 91 passed, 1 warning in 5.75s ==================================================
```

### Symbolic tests 
Not done yet, but the idea is to replace stack with sybolic values, make one symbolic step, concretize the pre-state variables, evaluate the results and check the correspondence with the post-state. TODO!

## Integration tests
Need to execute the whole block, and check with the trace. TODO!


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


