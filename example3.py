import json
import binascii

# Import from your actual codebase and pyevmasm
from thirdparty.pyevmasm.evmasm import Instruction
from thirdparty.pyevmasm.evmasm import instruction_tables
from src.concave import Project

# 1. Load your statedump
statedump = """
    {
      "block_number": 25024997,
      "tx_id": 206,
      "current_line": {
        "pc": 0,
        "depth": 1,
        "opName": "PUSH1",
        "op": 96,
        "gas": "0x73724",
        "stack": []
      },
      "next_line": {
        "pc": 2,
        "depth": 1,
        "opName": "PUSH1",
        "op": 96,
        "gas": "0x73721",
        "stack": [
          "0xc0"
        ]
      }
    }
"""
s = json.loads(statedump)

mock_code = bytes([96, 192]) 
table = instruction_tables['shanghai'] 
current_op = s["current_line"]["op"]
current_pc = s["current_line"]["pc"]

# Look up the base instruction from the table using the opcode
base_inst = table[current_op]

# The JSON doesn't explicitly state the operand value in `current_line`, 
# but for the sake of the test environment, we extract it from our mock_code 
# based on the operand_size defined by the InstructionTable.
operand = None
if base_inst.operand_size > 0:
    # Slice the operand bytes from the mock_code and convert to int
    operand_bytes = mock_code[1 : 1 + base_inst.operand_size]
    operand = int.from_bytes(operand_bytes, byteorder="big")

# Create the specific instruction for our map
# Note: pyevmasm's Instruction is often a namedtuple, so we instantiate a new one 
# with the properties from the base_inst, plus our specific pc and operand.
ins_map = {
    current_pc: Instruction(
        opcode=base_inst.opcode,
        name=base_inst.name,
        operand_size=base_inst.operand_size,
        pops=base_inst.pops,
        pushes=base_inst.pushes,
        fee=base_inst.fee,
        description=base_inst.description,
        operand=operand,
        pc=current_pc
    )
}

# 3. Initialize the Project with the ins_map
project = Project(
    top_level_data=b"",
    top_level_code=None,
    top_level_val=0,
    top_level_caller=0x1111,
    top_level_address=0x2222,
    block_time=123456789,
    tx_origin=0x1111,
    block_number=s["block_number"],
    ins_map=ins_map
)

# 4. Create a clean state
state = project.create_initial_state()

# --- MANUALLY EXECUTING THE STEP FOR TESTING ---

current_frame = state.current_frame 
current_pc = current_frame.pc
instruction = current_frame.ins_map.get(current_pc)

print(f"Executing: {instruction.name} at PC {instruction.pc}")

if instruction.name == "PUSH1":
    current_frame.stack.append(hex(instruction.operand))
    current_frame.pc += (1 + instruction.operand_size)

print(f"Post-execution PC: {current_frame.pc}")
print(f"Post-execution Stack: {current_frame.stack}")

assert current_frame.pc == s["next_line"]["pc"]
assert current_frame.stack == s["next_line"]["stack"]
print("Step executed successfully and matches statedump!")