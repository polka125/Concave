import json
import os
import pytest

from src.concave import Project
from thirdparty.pyevmasm.evmasm import osaka_instruction_table
from conftest import COVERED_OPCODES

def setup_simgr_from_trace(current_line: dict, operand_value: int = None):
    pc = current_line["pc"]
    instruction = osaka_instruction_table[current_line["op"]]
    instruction._pc = pc
    
    if operand_value is not None:
        instruction._operand = operand_value
        
    project = Project(
        top_level_data=b"", top_level_code=None, top_level_val=0,
        top_level_caller=0x1111, top_level_address=0x2222,
        block_time=123456789, tx_origin=0x1111, block_number=0,
        ins_map={pc: instruction}
    )
    
    simgr = project.create_simgr()
    frame = simgr.active[0].current_frame
    frame.pc = pc
    frame.stack = [int(x, 16) for x in current_line["stack"]]
    
    return simgr

def get_traces(opcode: str):
    trace_path = os.path.join("testdata", "concrete.json")
    if not os.path.exists(trace_path):
        pytest.skip(f"Trace file not found: {trace_path}")
        
    with open(trace_path, 'r') as f:
        traces = json.load(f).get(opcode, [])
        
    if not traces:
        pytest.skip(f"No {opcode} traces found.")
        
    # Use the shared set imported from conftest
    COVERED_OPCODES.add(opcode)
    return traces

@pytest.mark.parametrize("push_size", range(1, 33))
def test_push_concrete(push_size):
    opcode_name = f"PUSH{push_size}"
    for trace in get_traces(opcode_name):
        curr, nxt = trace["current_line"], trace["next_line"]
        pushed_val = int(nxt["stack"][-1], 16)
        
        simgr = setup_simgr_from_trace(curr, operand_value=pushed_val)
        simgr.step() 
        
        expected_stack = [int(x, 16) for x in nxt["stack"]]
        assert simgr.active[0].current_frame.stack == expected_stack

# Combine all opcodes that only require stack observation into one list
SIMPLE_STACK_OPCODES = [
    # Arithmetic
    "ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", 
    "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND",
    # Bitwise & Logic
    "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR", "SAR",
    # Comparisons
    "LT", "GT", "SLT", "SGT", "EQ", "ISZERO",
    # Basic Stack Operations
    "POP", "PUSH0", 
    # "CLZ" #todo
] + [f"DUP{i}" for i in range(1, 17)] + [f"SWAP{i}" for i in range(1, 17)]

@pytest.mark.parametrize("opcode_name", SIMPLE_STACK_OPCODES)
def test_simple_stack_concrete(opcode_name):
    for trace in get_traces(opcode_name):
        curr, nxt = trace["current_line"], trace["next_line"]
        
        simgr = setup_simgr_from_trace(curr)
        simgr.step()
        
        expected_stack = [int(x, 16) for x in nxt["stack"]]
        assert simgr.active[0].current_frame.stack == expected_stack
        
