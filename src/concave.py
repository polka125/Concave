import gzip
import json
import binascii
import logging
from typing import Any, Dict, List, Optional, Tuple
import os

from thirdparty.pyevmasm.evmasm import disassemble_all
import claripy
from data.known_data import address_to_code
from typing import Union


import web3
json_rpc_endpoint = os.getenv("WEB3_JSON_RPC", "http://localhost:8545")
w3 = web3.Web3(web3.HTTPProvider(json_rpc_endpoint))


# setup logging: 
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger('claripy').setLevel(logging.INFO)




DIFF_MODE = True
SYMBOLIC_SLOAD = False
SYMBOLIC_CALLDATA = True
HIDE_SYMBOLIC_VALS = True


decisions = ["MISS", "MISS", "MISS", "MISS", "TAKE"]
decisions_ptr = 0

decisions = []

def keccak256(data: bytes) -> bytes:
    """Pure Python Keccak-256 implementation (unchanged)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    
    S = [0] * 25
    
    def ROL64(a, n):
        n = n % 64
        return ((a << n) | (a >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
        
    RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 
          0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 
          0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a, 
          0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 
          0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a, 
          0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

    for i in range(0, len(padded), rate):
        block = padded[i:i+rate]
        for j in range(17):
            S[j] ^= int.from_bytes(block[j*8:(j+1)*8], 'little')
            
        for round_idx in range(24):
            C = [S[x] ^ S[x+5] ^ S[x+10] ^ S[x+15] ^ S[x+20] for x in range(5)]
            D = [C[(x-1)%5] ^ ROL64(C[(x+1)%5], 1) for x in range(5)]
            for x in range(5):
                for y in range(0, 25, 5):
                    S[x+y] ^= D[x]
                    
            x, y = 1, 0
            current = S[x + 5*y]
            for t in range(24):
                x, y = y, (2*x + 3*y) % 5
                shift = ((t+1)*(t+2)//2) % 64
                temp = S[x + 5*y]
                S[x + 5*y] = ROL64(current, shift)
                current = temp
                
            for y in range(0, 25, 5):
                temp = S[y:y+5]
                for x in range(5):
                    S[y+x] = (temp[x] ^ ((~temp[(x+1)%5]) & temp[(x+2)%5])) & 0xFFFFFFFFFFFFFFFF
                    
            S[0] ^= RC[round_idx]
            
    out = bytearray()
    for i in range(4):
        out.extend(S[i].to_bytes(8, 'little'))
    return bytes(out)




def is_concrete(a):
    return isinstance(a, int) or (isinstance(a, claripy.ast.BV) and a.concrete)


def get_concrete(a): 
    if isinstance(a, int):
        return a
    elif isinstance(a, claripy.ast.BV) and a.concrete:
        return a.concrete_value
    else:
        raise ValueError("Argument is not concrete")

def to_signed(val):
    return val if val < 2**255 else val - 2**256

def from_signed(val):
    return val if val >= 0 else val + 2**256

def get_slice(data, offset, size) -> claripy.ast.BV | bytes:
    if isinstance(data, bytes):
        return data[offset:offset+size]
    elif isinstance(data, claripy.ast.BV):
        res = data.get_bytes(offset, size)
        if res.concrete: 
            num = res.concrete_value
            return num.to_bytes(size, byteorder='big')
        else:
            return res            
    else:
        raise TypeError("Unsupported data type for slicing")




def get_storage_rpc(block: int, contract: Union[str, bytes, int], slot: int) -> int:
    if isinstance(contract, int):
        contract_hex = f"0x{contract:040x}"
    elif isinstance(contract, bytes):
        contract_hex = "0x" + contract.hex()
    else:
        contract_hex = contract

    checksum_address = w3.to_checksum_address(contract_hex)
    storage_data = w3.eth.get_storage_at(checksum_address, slot, block_identifier=block-1)
    return int.from_bytes(storage_data, byteorder='big')



from typing import Optional, Union

def get_code_rpc(block: Optional[int], contract: Union[str, bytes, int]) -> bytes:
    if isinstance(contract, int):
        contract_hex = f"0x{contract:040x}"
    elif isinstance(contract, bytes):
        contract_hex = "0x" + contract.hex()
    else:
        contract_hex = contract
        
    checksum_address = w3.to_checksum_address(contract_hex)
    bytecode = bytes(w3.eth.get_code(checksum_address, block_identifier=block))
    
    # Handle EIP-7702 Delegation
    # The bytecode format is 0xef0100 (3 bytes) followed by the 20-byte address
    if len(bytecode) == 23 and bytecode.startswith(b"\xef\x01\x00"):
        delegated_address = bytecode[3:23]
        return get_code_rpc(block, delegated_address)
        
    return bytecode

class Frame:
    """Represents an execution context (one call frame)."""
    def __init__(
        self, 
        code: bytes, 
        calldata: bytes, 
        address: int, 
        caller: int, 
        value: int, 
        is_static: bool, 
        ins_map: Optional[Dict[int, Any]] = None, 
        return_info: Optional[Tuple[int, int, int]] = None
    ) -> None:
        self.pc: int = 0
        self.stack: List[Any] = []
        self.memory: Dict[int, Any] = {}
        
        self.code: bytes = code
        self.calldata: bytes = calldata
        self.address: int = address      
        self.caller: int = caller        
        self.value: int = value          
        
        self.is_static: bool = is_static
        self.ins_map: Dict[int, Any] = ins_map or {}
        self.return_info: Optional[Tuple[int, int, int]] = return_info

    def copy(self) -> 'Frame':
        new_frame = Frame(
            self.code, self.calldata, self.address, self.caller, 
            self.value, self.is_static, self.ins_map, self.return_info
        )
        new_frame.pc = self.pc
        new_frame.stack = list(self.stack)
        new_frame.memory = dict(self.memory)
        return new_frame


class EVMState:
    """Represents the global state of the blockchain and the solver."""
    def __init__(self, tx_origin: int, block_time: int, block_number: Optional[int] = None) -> None:
        self.tx_origin: int = tx_origin  
        self.block_time: int = block_time 
        
        self.block_number: Optional[int] = block_number

        self.storage: Dict[Any, Any] = {} 
        self.s_vars: List[Any] = []
        self.constraints: List[Any] = []
        self.call_stack: List[Frame] = []
        self.error: Optional[str] = None 
        
        self.step: int = 0
        self.last_return_data: bytearray = bytearray()
        self.success: Optional[int] = None

    @property
    def current_frame(self) -> Optional[Frame]:
        return self.call_stack[-1] if self.call_stack else None

    def push_frame(self, frame: Frame) -> None:
        self.call_stack.append(frame)

    def pop_frame(self) -> Frame:
        return self.call_stack.pop()

    def copy(self) -> 'EVMState':
        new_state = EVMState(self.tx_origin, self.block_time, self.block_number)
        new_state.storage = dict(self.storage) 
        new_state.s_vars = list(self.s_vars)
        new_state.constraints = list(self.constraints)
        new_state.call_stack = [frame.copy() for frame in self.call_stack]
        new_state.error = self.error
        new_state.step = self.step
        new_state.last_return_data = bytearray(self.last_return_data)
        new_state.success = self.success
        return new_state


class Engine:
    def __init__(self):
        self.stateless_solver = claripy.Solver()

    def try_concretize(self, expr):
        "returns (concrete_value, is_concrete)"
        if isinstance(expr, int) or isinstance(expr, bytes):
            return expr, True
        elif isinstance(expr, claripy.ast.BV) and expr.concrete:
            return expr.concrete_value, True
        else:
            res = self.stateless_solver.eval(expr, 2)
            if len(res) == 1:
                return res[0], True
        return expr, False

    def try_concretize_with_constraints(self, expr, constraints):
        "returns (concrete_value, is_concrete)"
        if isinstance(expr, int) or isinstance(expr, bytes):
            return expr, True
        elif isinstance(expr, claripy.ast.BV) and expr.concrete:
            return expr.concrete_value, True
        else:
            solver = claripy.Solver()
            for c in constraints:
                solver.add(c)
            res = solver.eval(expr, 2)
            if len(res) == 1:
                return res[0], True
        return expr, False


    def _handle_return(self, state: EVMState, success: int, return_data: bytearray) -> Tuple[List[EVMState], List[EVMState]]:
        """Helper to handle frame popping and returning data to the parent frame."""
        state.pop_frame()
        if not state.call_stack:
            # Top-level execution finished
            state.success = success
            state.last_return_data = return_data
            return [], [state]
        
        if state.current_frame is None:
            raise RuntimeError("Expected a parent frame after popping, but call stack is empty.")
        
        parent: Frame = state.current_frame
        if parent.return_info is not None:
            next_pc, ret_offset, ret_size = parent.return_info
            parent.return_info = None
            write_size = min(ret_size, len(return_data))
            for i in range(write_size):
                parent.memory[ret_offset + i] = return_data[i]
            parent.stack.append(success)
            parent.pc = next_pc
            state.last_return_data = return_data
            
        return [state], []


    def print_state(self, state: EVMState, project: 'Project'):
        # Debug Output
        current = state.current_frame
        if current is None:
            return 
        prev_ins = getattr(state, 'prev_ins', None)
        curr_ins = current.ins_map[current.pc]

        prev_pc = prev_ins.pc if prev_ins else None
        if prev_pc:
            print(f"{prev_pc:08x}: {curr_ins.name}; step({state.step}) stack_size({len(current.stack)})")

        formatted_stack = []
        for item in current.stack:
            if isinstance(item, claripy.ast.BV) and item.concrete and HIDE_SYMBOLIC_VALS:
                formatted_stack.append(hex(item.concrete_value))
            elif isinstance(item, int):
                formatted_stack.append(hex(item))
            elif isinstance(item, bytes):
                formatted_stack.append("0x" + item.hex())
            else:
                item_concr, resp = self.try_concretize(item)
                if resp and HIDE_SYMBOLIC_VALS:
                    formatted_stack.append(hex(item_concr))
                else:
                    formatted_stack.append(str(item_concr))

        indent = "  " * (len(state.call_stack) - 1)

        if DIFF_MODE:
            s1 = f"{formatted_stack}"
            s2 = f"{project.debug_stack[state.step]['stack'] if state.step < len(project.debug_stack) else 'N/A'}"

            print(f"{indent}{s1}")
            print(f"{indent}{s2}")
            if s1 != s2:
                print(f"{indent}>>> Stack mismatch detected!")
        else:
            print(f"{indent}   Stack: {formatted_stack}")      

        op = str(hex(curr_ins.operand)) if curr_ins.operand is not None else ""
        print(f"{curr_ins.pc:08x}: {curr_ins.name} {op}; step({state.step}) stack_size({len(current.stack)})\n\n")


    def print_state_2(self, state: EVMState, project: 'Project'):
        current = state.current_frame
        if current is None:
            return 
            
        curr_ins = current.ins_map[current.pc]
        indent = "  " * (len(state.call_stack) - 1)
        indent = ""

        # 1. Format the Stack
        formatted_stack = []
        for item in current.stack:
            if isinstance(item, claripy.ast.BV) and item.concrete and HIDE_SYMBOLIC_VALS:
                formatted_stack.append(hex(item.concrete_value))
            elif isinstance(item, int):
                formatted_stack.append(hex(item))
            elif isinstance(item, bytes):
                formatted_stack.append("0x" + item.hex())
            else:
                item_concr, resp = self.try_concretize(item)
                if resp and HIDE_SYMBOLIC_VALS:
                    formatted_stack.append(hex(item_concr))
                else:
                    formatted_stack.append(str(item_concr))

        # 2. Format the Current Instruction
        op = f" {hex(curr_ins.operand)}" if curr_ins.operand is not None else ""
        
        # 3. Print Header
        print(f"{indent}--------------------------------------------------")
        print(f"{indent}[Step {state.step:04d}] PC: {curr_ins.pc:08x} | {curr_ins.name}{op} | stack_size: {len(current.stack)}")
        
        # 4. Print Stack & Diffs
        if DIFF_MODE:
            s1 = f"{formatted_stack}"
            s2 = f"{project.debug_stack[state.step]['stack'] if state.step < len(project.debug_stack) else 'N/A'}"

            print(f"{indent}  Ours: {s1}")
            print(f"{indent}  Refs: {s2}")
            if s1 != s2:
                print(f"{indent}  >>> STACK MISMATCH DETECTED! <<<")
        else:
            print(f"{indent}  Stack: {formatted_stack}")      
            
        print(f"{indent}--------------------------------------------------")

    def succ(self, state: EVMState, project: 'Project') -> Tuple[List[EVMState], List[EVMState]]:
        current = state.current_frame
        if current is None:
            return [], [state]

        # Lazy disassembly
        if not current.ins_map:
            current.ins_map = {ins.pc: ins for ins in disassemble_all(current.code, pc=0, fork='osaka')}
        
        if current.pc not in current.ins_map:
            # Invalid PC -> fail and return
            return self._handle_return(state, 0, bytearray())

        curr_ins = current.ins_map[current.pc]

        auto_increment_pc = True
        self.print_state_2(state, project)

        state.prev_ins = curr_ins

        state.step += 1

        # --- OPCODES ---
        if curr_ins.name == "STOP":
            return self._handle_return(state, 1, bytearray())

        elif curr_ins.name == "ADD":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val): # is_concrete: unbound variable 
                current.stack.append((get_concrete(a_val) + get_concrete(b_val)) % (2**256))
            else:
                current.stack.append(a_val + b_val)

        elif curr_ins.name == "MUL":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                current.stack.append((get_concrete(a_val) * get_concrete(b_val)) % (2**256))
            else:
                current.stack.append(a_val * b_val)

        elif curr_ins.name == "SUB":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                current.stack.append((get_concrete(a_val) - get_concrete(b_val)) % (2**256))
            else:
                current.stack.append(a_val - b_val)

        elif curr_ins.name == "DIV":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                a_int, b_int = get_concrete(a_val), get_concrete(b_val)
                current.stack.append(0 if b_int == 0 else a_int // b_int)
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                # trick: prevent division by zero                 
                safe_b = claripy.If(b_sym == 0, claripy.BVV(1, 256), b_sym)
                
                res = claripy.If(b_sym == 0, claripy.BVV(0, 256), a_sym / safe_b)
                current.stack.append(res)

        elif curr_ins.name == "SDIV":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                a_int, b_int = to_signed(get_concrete(a_val)), to_signed(get_concrete(b_val))
                if b_int == 0:
                    current.stack.append(0)
                elif a_int == -2**255 and b_int == -1:
                    current.stack.append(from_signed(-2**255))
                else:
                    sign = -1 if (a_int * b_int) < 0 else 1
                    current.stack.append(from_signed(sign * (abs(a_int) // abs(b_int))))
            else:
                # Ensure both are claripy BVs
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                
                is_zero = (b_sym == 0)
                is_overflow = claripy.And(a_sym == claripy.BVV(1 << 255, 256), b_sym == claripy.BVV(-1, 256))
                
                safe_b = claripy.If(is_zero, claripy.BVV(1, 256), b_sym)
                sdiv_res = claripy.SDiv(a_sym, safe_b)
                res = claripy.If(is_zero, claripy.BVV(0, 256), claripy.If(is_overflow, a_sym, sdiv_res))
                current.stack.append(res)

        elif curr_ins.name == "MOD":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                a_int, b_int = get_concrete(a_val), get_concrete(b_val)
                current.stack.append(0 if b_int == 0 else a_int % b_int)
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                
                # Trick: Prevent modulo by zero in the AST itself
                safe_b = claripy.If(b_sym == 0, claripy.BVV(1, 256), b_sym)
                
                res = claripy.If(b_sym == 0, claripy.BVV(0, 256), a_sym % safe_b)
                current.stack.append(res)

        elif curr_ins.name == "SMOD":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                a_int, b_int = to_signed(get_concrete(a_val)), to_signed(get_concrete(b_val))
                if b_int == 0:
                    current.stack.append(0)
                else:
                    sign = -1 if a_int < 0 else 1
                    current.stack.append(from_signed(sign * (abs(a_int) % abs(b_int))))
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                safe_b = claripy.If(b_sym == 0, claripy.BVV(1, 256), b_sym)                
                res = claripy.If(b_sym == 0, claripy.BVV(0, 256), claripy.SMod(a_sym, safe_b))
                current.stack.append(res)

        elif curr_ins.name == "ADDMOD":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            N = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val) and is_concrete(N):
                a_int, b_int, n_int = get_concrete(a_val), get_concrete(b_val), get_concrete(N)
                current.stack.append(0 if n_int == 0 else (a_int + b_int) % n_int)
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                n_sym = N if isinstance(N, claripy.ast.BV) else claripy.BVV(N, 256)
                
                # ADDMOD does addition in arbitrary precision before modulo, so we zero-extend to 512 bits
                a_ext = claripy.ZeroExt(256, a_sym)
                b_ext = claripy.ZeroExt(256, b_sym)
                n_ext = claripy.ZeroExt(256, n_sym)
                
                safe_n = claripy.If(n_ext == 0, claripy.BVV(1, 512), n_ext)
                res_ext = claripy.If(n_ext == 0, claripy.BVV(0, 512), (a_ext + b_ext) % safe_n)
                current.stack.append(claripy.Extract(255, 0, res_ext))

        elif curr_ins.name == "MULMOD":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            N = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val) and is_concrete(N):
                a_int, b_int, n_int = get_concrete(a_val), get_concrete(b_val), get_concrete(N)
                current.stack.append(0 if n_int == 0 else (a_int * b_int) % n_int)
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                n_sym = N if isinstance(N, claripy.ast.BV) else claripy.BVV(N, 256)
                
                # MULMOD does multiplication in arbitrary precision before modulo
                a_ext = claripy.ZeroExt(256, a_sym)
                b_ext = claripy.ZeroExt(256, b_sym)
                n_ext = claripy.ZeroExt(256, n_sym)
                
                safe_n = claripy.If(n_ext == 0, claripy.BVV(1, 512), n_ext)
                res_ext = claripy.If(n_ext == 0, claripy.BVV(0, 512), (a_ext * b_ext) % safe_n)
                current.stack.append(claripy.Extract(255, 0, res_ext))

        elif curr_ins.name == "EXP":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            current.stack.append(pow(a_val, b_val, 2**256))

        elif curr_ins.name == "SIGNEXTEND":
            b_val = current.stack.pop()
            x = current.stack.pop()
            if b_val < 31:
                sign_bit = (x >> (b_val * 8 + 7)) & 1
                mask = (1 << (b_val * 8 + 8)) - 1
                if sign_bit:
                    x = x | ((2**256 - 1) ^ mask)
                else:
                    x = x & mask
            current.stack.append(x)

        elif curr_ins.name == "LT":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                current.stack.append(1 if get_concrete(a_val) < get_concrete(b_val) else 0)
            else:
                current.stack.append(claripy.If(claripy.ULT(a_val, b_val), claripy.BVV(1, 256), claripy.BVV(0, 256)))

        elif curr_ins.name == "GT":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                current.stack.append(1 if get_concrete(a_val) > get_concrete(b_val) else 0)
            else: 
                current.stack.append(claripy.If(claripy.UGT(a_val, b_val), claripy.BVV(1, 256), claripy.BVV(0, 256)))

        elif curr_ins.name == "SLT":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                a_int = to_signed(get_concrete(a_val))
                b_int = to_signed(get_concrete(b_val))
                current.stack.append(1 if a_int < b_int else 0)
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                current.stack.append(claripy.If(claripy.SLT(a_sym, b_sym), claripy.BVV(1, 256), claripy.BVV(0, 256)))

        elif curr_ins.name == "SGT":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                a_int = to_signed(get_concrete(a_val))
                b_int = to_signed(get_concrete(b_val))
                current.stack.append(1 if a_int > b_int else 0)
            else:
                a_sym = a_val if isinstance(a_val, claripy.ast.BV) else claripy.BVV(a_val, 256)
                b_sym = b_val if isinstance(b_val, claripy.ast.BV) else claripy.BVV(b_val, 256)
                current.stack.append(claripy.If(claripy.SGT(a_sym, b_sym), claripy.BVV(1, 256), claripy.BVV(0, 256)))

        elif curr_ins.name == "EQ":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            if is_concrete(a_val) and is_concrete(b_val):
                current.stack.append(1 if get_concrete(a_val) == get_concrete(b_val) else 0)
            else:
                current.stack.append(claripy.If(a_val == b_val, claripy.BVV(1, 256), claripy.BVV(0, 256)))

        elif curr_ins.name == "ISZERO":
            a_val = current.stack.pop()
            if is_concrete(a_val):
                current.stack.append(1 if get_concrete(a_val) == 0 else 0)
            else:
                expr = claripy.If(a_val == 0, claripy.BVV(1, 256), claripy.BVV(0, 256))
                current.stack.append(expr)

        elif curr_ins.name == "AND":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            current.stack.append(a_val & b_val)

        elif curr_ins.name == "OR":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            current.stack.append(a_val | b_val)

        elif curr_ins.name == "XOR":
            a_val = current.stack.pop()
            b_val = current.stack.pop()
            current.stack.append(a_val ^ b_val)

        elif curr_ins.name == "NOT":
            a_val = current.stack.pop()
            current.stack.append(~a_val & (2**256 - 1))

        elif curr_ins.name == "BYTE":
            index = current.stack.pop()
            value = current.stack.pop()
            if index < 32:
                current.stack.append((value >> (8 * (31 - index))) & 0xFF)
            else:
                current.stack.append(0)

        elif curr_ins.name == "SHL":
            shift = current.stack.pop()
            value = current.stack.pop()
            current.stack.append(0 if shift >= 256 else (value << shift) & (2**256 - 1))

        elif curr_ins.name == "SHR":
            shift = current.stack.pop()
            value = current.stack.pop()
            if is_concrete(shift) and is_concrete(value):
                shift_int, val_int = get_concrete(shift), get_concrete(value)
                current.stack.append(0 if shift_int >= 256 else val_int >> shift_int)
            else:
                current.stack.append(claripy.If(shift >= 256, claripy.BVV(0, 256), claripy.LShR(value, shift)))

        elif curr_ins.name == "SAR":
            shift = current.stack.pop()
            value = current.stack.pop()
            if is_concrete(shift) and is_concrete(value):
                shift_int = get_concrete(shift)
                val_int = to_signed(get_concrete(value))
                if shift_int >= 256:
                    current.stack.append(from_signed(-1 if val_int < 0 else 0))
                else:
                    current.stack.append(from_signed(val_int >> shift_int))
            else:
                shift_sym = shift if isinstance(shift, claripy.ast.BV) else claripy.BVV(shift, 256)
                val_sym = value if isinstance(value, claripy.ast.BV) else claripy.BVV(value, 256)
                is_neg = claripy.SLT(val_sym, claripy.BVV(0, 256))
                sign_extended = claripy.If(is_neg, claripy.BVV(-1, 256), claripy.BVV(0, 256))
                
                res = claripy.If(claripy.UGE(shift_sym, claripy.BVV(256, 256)), 
                                 sign_extended, 
                                 val_sym >> shift_sym)
                current.stack.append(res)

        elif curr_ins.name in ("SHA3", "KECCAK256"):
            offset = current.stack.pop()
            size = current.stack.pop()
            data_to_hash = bytearray()
            for i in range(size):
                data_to_hash.append(current.memory.get(offset + i, 0))
            current.stack.append(int.from_bytes(keccak256(data_to_hash), 'big'))

        elif curr_ins.name == "ADDRESS":
            current.stack.append(current.address)

        elif curr_ins.name == "BALANCE":
            current.stack.pop()
            current.stack.append(10**18)

        elif curr_ins.name == "ORIGIN":
            current.stack.append(state.tx_origin)

        elif curr_ins.name == "CALLER":
            current.stack.append(current.caller)

        elif curr_ins.name == "CALLVALUE":
            current.stack.append(current.value)

        elif curr_ins.name == "CALLDATALOAD":
            offset = current.stack.pop()
            if isinstance(current.calldata, claripy.ast.bv.BV):

                # concretize offset 
                offset_concr, is_concr = self.try_concretize(offset)
                if not is_concr:
                    raise ValueError("Offset for CALLDATALOAD must be concretizable")
                sliced = get_slice(current.calldata, offset_concr, 32)
                if isinstance(sliced, bytes):
                    current.stack.append(int.from_bytes(sliced, byteorder='big'))
                else:
                    current.stack.append(sliced)
            else:
                loaded_bytes = bytes(current.calldata[offset:offset+32])
                if len(loaded_bytes) < 32:
                    loaded_bytes += b'\x00' * (32 - len(loaded_bytes))
                current.stack.append(int.from_bytes(loaded_bytes, byteorder='big'))

        elif curr_ins.name == "CALLDATASIZE":
            if isinstance(current.calldata, claripy.ast.bv.BV):
                current.stack.append(current.calldata.size() // 8)
            else:
                current.stack.append(len(current.calldata))

        elif curr_ins.name == "CALLDATACOPY":
            destOffset = current.stack.pop()
            offset = current.stack.pop()
            size = current.stack.pop()
            for i in range(size):
                if offset + i < len(current.calldata):
                    current.memory[destOffset + i] = current.calldata[offset + i]
                else:
                    current.memory[destOffset + i] = 0

        elif curr_ins.name == "CODESIZE":
            current.stack.append(len(current.code))

        elif curr_ins.name == "CODECOPY":
            destOffset = current.stack.pop()
            offset = current.stack.pop()
            size = current.stack.pop()
            for i in range(size):
                if offset + i < len(current.code):
                    current.memory[destOffset + i] = current.code[offset + i]
                else:
                    current.memory[destOffset + i] = 0

        elif curr_ins.name == "GASPRICE":
            logger.error("GASPRICE opcode encountered! This should not happen in a stateless analysis context.")
            current.stack.append(20 * 10**9)

        elif curr_ins.name == "EXTCODESIZE":
            target_address = current.stack.pop()
            if is_concrete(target_address):
                target_address = get_concrete(target_address)
                if target_address in address_to_code:
                    current.stack.append(len(address_to_code[target_address]))
                else:
                    current.stack.append(0)
            else:
                slvr = claripy.Solver()
                res = slvr.eval(target_address, 2)  # Just to trigger any potential simplifications
                if len(res) == 1:
                    target_address = res[0]
                    if target_address in address_to_code:
                        current.stack.append(len(address_to_code[target_address]))
                    else:
                        current.stack.append(0)
                else:
                    symbolic_size = claripy.BVS(f"extcodesize_{target_address}", 256)
                    current.stack.append(symbolic_size)
                    state.s_vars.append(symbolic_size)

        elif curr_ins.name == "EXTCODECOPY":
            for _ in range(4): current.stack.pop()

        elif curr_ins.name == "RETURNDATASIZE":
            current.stack.append(len(state.last_return_data))

        elif curr_ins.name == "RETURNDATACOPY":
            dest_offset = current.stack.pop()
            offset = current.stack.pop()
            size = current.stack.pop()
            for i in range(size):
                if offset + i < len(state.last_return_data):
                    current.memory[dest_offset + i] = state.last_return_data[offset + i]
                else:
                    current.memory[dest_offset + i] = 0

        elif curr_ins.name == "EXTCODEHASH":
            current.stack.pop()
            current.stack.append(0)

        elif curr_ins.name == "BLOCKHASH":
            current.stack.pop()
            current.stack.append(0xabc123)

        elif curr_ins.name == "COINBASE":
            current.stack.append(0x0000000000000000000000000000000000000000)

        elif curr_ins.name == "TIMESTAMP":
            current.stack.append(state.block_time)

        elif curr_ins.name == "NUMBER":
            logger.error("NUMBER opcode encountered!")
            current.stack.append(10000000)

        elif curr_ins.name in ("PREVRANDAO", "DIFFICULTY"):
            current.stack.append(0x445566)

        elif curr_ins.name == "GASLIMIT":
            current.stack.append(30000000)

        elif curr_ins.name == "CHAINID":
            current.stack.append(1)

        elif curr_ins.name == "SELFBALANCE":
            current.stack.append(10**18)

        elif curr_ins.name == "BASEFEE":
            current.stack.append(15 * 10**9)

        elif curr_ins.name == "POP":
            current.stack.pop()

        elif curr_ins.name == "MLOAD":
            offset = current.stack.pop()
            val_mem = 0
            for i in range(32):
                val_mem = (val_mem << 8) | current.memory.get(offset + i, 0)
                if offset + i not in current.memory:
                    current.memory[offset + i] = 0
            current.stack.append(val_mem)

        elif curr_ins.name == "MSTORE":
            offset = current.stack.pop()
            value = current.stack.pop()
            for i in range(31, -1, -1):
                current.memory[offset + i] = value & 0xFF
                value >>= 8

        elif curr_ins.name == "MSTORE8":
            offset = current.stack.pop()
            value = current.stack.pop() & 0xFF
            current.memory[offset] = value

        elif curr_ins.name == "OLD_SLOAD": # to delete
            key = current.stack.pop()
            if key in state.storage:
                current.stack.append(state.storage[key])
            elif SYMBOLIC_SLOAD: 
                symbolic_value = claripy.BVS(f"storage_{key}", 256)
                current.stack.append(symbolic_value)
                state.storage[key] = symbolic_value
                state.s_vars.append(symbolic_value)
            elif state.step <= len(project.debug_stack):
                key_debug = int(project.debug_stack[state.step]['stack'][-1], 16)
                current.stack.append(key_debug)
            else:
                current.stack.append(state.storage.get(key, 0))
        elif curr_ins.name == "SLOAD":
            key_expr = current.stack.pop()
            key_concrete, is_key_concrete = self.try_concretize_with_constraints(key_expr, state.constraints)            
            if not is_key_concrete:
                raise ValueError(f"SLOAD error: Storage key could not be concretized. Key expr: {key_expr}")

            if key_concrete in state.storage:
                value = state.storage[key_concrete]
            else:
                contract_address = current.address 
                block_number = state.block_number
                if not block_number: 
                    raise ValueError("SLOAD error: block number is not set")

                value = get_storage_rpc(block_number, contract_address, key_concrete)
                state.storage[key_concrete] = value                
            current.stack.append(value)

        elif curr_ins.name == "SSTORE":
            key = current.stack.pop()
            value = current.stack.pop()
            if current.is_static:
                print(f"{indent}State modification during STATICCALL! Reverting.")
                return self._handle_return(state, 0, bytearray())
            state.storage[key] = value

        elif curr_ins.name == "JUMP":
            dest = current.stack.pop()
            current.pc = dest
            auto_increment_pc = False

        elif curr_ins.name == "JUMPI":
            dest = current.stack.pop()
            cond = current.stack.pop()
            
            if isinstance(cond, (int, bytes)):
                if cond != 0:
                    current.pc = dest
                    auto_increment_pc = False
            elif is_concrete(cond):
                if get_concrete(cond) != 0:
                    current.pc = dest
                    auto_increment_pc = False
            elif isinstance(cond, claripy.ast.BV):
                # first try to eval using solver 
                slvr = claripy.Solver()
                for constraint in state.constraints:
                    slvr.add(constraint)

                jumpcond = (cond != 0)
                evalres = slvr.eval(jumpcond, 2)
                if len(evalres) == 1:
                    if evalres[0] == 1:
                        current.pc = dest
                        auto_increment_pc = False
                else:
                    global decisions_ptr, decisions
                    if decisions_ptr < len(decisions):
                        decision_type = (decisions[decisions_ptr] == "TAKE")
                        decisions_ptr += 1
                        state.constraints.append((cond != 0) == decision_type)
                        if decision_type:
                            current.pc = dest
                            auto_increment_pc = False
                    else:
                        print(f">>>>>>>>>>> Forking at JUMPI with symbolic condition: {cond}")
                        logger.debug(f"Forking at JUMPI with symbolic condition: {cond}")
                        state_true = state.copy()
                        assert state_true.current_frame is not None 
                        state_true.constraints.append(cond != 0)
                        state_true.current_frame.pc = dest
                        
                        state_false = state 
                        assert state_false.current_frame is not None
                        state_false.constraints.append(cond == 0)
                        state_false.current_frame.pc += 1 + curr_ins.operand_size
                        
                        return [state_true, state_false], []
        elif curr_ins.name == "PC":
            current.stack.append(current.pc)

        elif curr_ins.name == "MSIZE":
            if current.memory:
                current.stack.append(((max(current.memory.keys()) + 1 + 31) // 32) * 32)
            else:
                current.stack.append(0)

        elif curr_ins.name == "GAS":
            if state.step < len(project.debug_stack):
                expected_gas = int(project.debug_stack[state.step]['stack'][-1], 16)
                current.stack.append(expected_gas)
            else:
                current.stack.append(30000000)

        elif curr_ins.name == "JUMPDEST":
            pass

        elif curr_ins.name == "PUSH0":
            current.stack.append(0)

        elif curr_ins.name.startswith("PUSH"):
            current.stack.append(curr_ins.operand)

        elif curr_ins.name.startswith("DUP"):
            n = int(curr_ins.name[3:])
            current.stack.append(current.stack[-n])

        elif curr_ins.name.startswith("SWAP"):
            n = int(curr_ins.name[4:])
            current.stack[-1], current.stack[-1-n] = current.stack[-1-n], current.stack[-1]
            if state.step >= 470:
                breakpoint = True

        elif curr_ins.name.startswith("LOG"):
            n = int(curr_ins.name[3:])
            current.stack.pop()
            current.stack.pop()
            for _ in range(n):
                current.stack.pop()

        elif curr_ins.name == "CREATE":
            for _ in range(3): current.stack.pop()
            current.stack.append(0x1234567890123456789012345678901234567890)


        elif curr_ins.name in ("CALL", "CALLCODE", "STATICCALL", "DELEGATECALL"):
            gas = current.stack.pop()
            target_address = current.stack.pop()
            
            if is_concrete(target_address):
                target_address = get_concrete(target_address)
            else:
                slvr = claripy.Solver()
                for constraint in state.constraints:
                    slvr.add(constraint)
                res = slvr.eval(target_address, 2)
                if len(res) == 1:
                    target_address = res[0]
                elif len(res) == 0:
                    raise Exception("No possible value??")
                else:
                    print(f">>>>>>>>>>> HAVE SYMBOLIC TARGET ADDRESS: {target_address} THAT BAD")
                    target_address = target_address # Symbolic fallback

            call_value = 0
            if curr_ins.name in ("CALL", "CALLCODE"):
                call_value = current.stack.pop()
                
            args_offset = current.stack.pop()
            args_size = current.stack.pop()
            ret_offset = current.stack.pop()
            ret_size = current.stack.pop()

            if is_concrete(args_offset): 
                args_offset = get_concrete(args_offset)
            else:
                slvr = claripy.Solver()
                for constraint in state.constraints:
                    slvr.add(constraint)
                res = slvr.eval(args_offset, 2)
                if len(res) == 1:
                    args_offset = res[0]
                elif len(res) == 0:
                    raise Exception("No possible value??")
                else:
                    print(f">>>>>>>>>>> HAVE SYMBOLIC ARGS OFFSET: {args_offset} THAT BAD")
                    args_offset = args_offset # Symbolic fallback

            if is_concrete(args_size):
                args_size = get_concrete(args_size)
            else:
                slvr = claripy.Solver()
                for constraint in state.constraints:
                    slvr.add(constraint)
                res = slvr.eval(args_size, 2)
                if len(res) == 1:
                    args_size = res[0]
                elif len(res) == 0:
                    raise Exception("No possible value??")
                else:
                    print(f">>>>>>>>>>> HAVE SYMBOLIC ARGS SIZE: {args_size} THAT BAD")
                    args_size = args_size 

            memory_elements = []
            for i in range(args_size):
                val = current.memory.get(args_offset + i, 0)
                memory_elements.append(val)
            is_symbolic_calldata = any(isinstance(x, claripy.ast.BV) for x in memory_elements)

            if is_symbolic_calldata:
                bv_elements = []
                for x in memory_elements:
                    if isinstance(x, claripy.ast.BV):
                        bv_elements.append(x)
                    else:
                        bv_elements.append(claripy.BVV(x, 8))                
                if bv_elements:
                    sub_calldata = claripy.Concat(*bv_elements)
                else:
                    sub_calldata = claripy.BVV(0, 0) # Fallback for 0-size calldata
            else:
                sub_calldata = bytearray(memory_elements)

            target_code = b""
            if isinstance(target_address, int):
                target_code = address_to_code.get(target_address, b"")
                if target_code == b"": 
                    target_code = get_code_rpc(state.block_number, target_address)
                    address_to_code[target_address] = target_code

            if current.is_static and call_value > 0:
                current.stack.append(0)
            elif target_code != b"":
                next_pc = current.pc + 1 + curr_ins.operand_size
                current.return_info = (next_pc, ret_offset, ret_size)
                
                child_state = EVMState(state.tx_origin, state.block_time)
                
                child_frame = Frame(
                    code=target_code,
                    calldata=sub_calldata,
                    address=target_address if curr_ins.name in ("CALL", "STATICCALL") else current.address,
                    caller=current.address if curr_ins.name in ("CALL", "STATICCALL") else current.caller,
                    value=call_value if curr_ins.name != "DELEGATECALL" else current.value,
                    is_static=(current.is_static or curr_ins.name == "STATICCALL"),
                )
                state.push_frame(child_frame)
                auto_increment_pc = False
            else:
                state.last_return_data = bytearray()
                current.stack.append(1)

        elif curr_ins.name in ("RETURN", "REVERT"):
            ret_offset = current.stack.pop()
            ret_size = current.stack.pop()
            return_data = bytearray()
            for i in range(ret_size):
                return_data.append(current.memory.get(ret_offset + i, 0))
            success = 1 if curr_ins.name == "RETURN" else 0
            return self._handle_return(state, success, return_data)

        elif curr_ins.name == "CREATE2":
            for _ in range(4): current.stack.pop()
            current.stack.append(0x1234567890123456789012345678901234567890)

        elif curr_ins.name == "INVALID":
            return self._handle_return(state, 0, bytearray())

        elif curr_ins.name == "SELFDESTRUCT":
            current.stack.pop()
            return self._handle_return(state, 1, bytearray())
        elif curr_ins.name == "BLOBBASEFEE":
            raise NotImplementedError(f"{curr_ins.name} is not implemented yet")
        elif curr_ins.name == "CLZ":
            raise NotImplementedError(f"{curr_ins.name} is not implemented yet")


        else:
            # Unknown instruction
            return self._handle_return(state, 0, bytearray())

        if auto_increment_pc:
            current.pc += 1 + curr_ins.operand_size

        return [state], []


class SimulationManager:
    """Manages execution states and mitigates path explosion."""
    def __init__(self, initial_state: EVMState, project: 'Project') -> None:
        self.active: List[EVMState] = [initial_state]  
        self.finished: List[EVMState] = []
        self.project = project
        self.engine = Engine()

    def step(self) -> None:
        current_active: List[EVMState] = self.active
        self.active = []

        for state in current_active:
            try:
                active, finished = self.engine.succ(state, self.project)

                for s in active:
                    self.active.append(s)
                for s in finished:
                    self.finished.append(s)
            except Exception as e:
                self.finished.append(state)
                print(f"Error during execution: {e} of state: {state}")
                logger.error(f"Error during execution: {e}")
                logger.debug(f"State at error: {state}")
                continue

    def run(self) -> None:
        """Runs the simulation until no active states remain."""
        while self.active:
            self.step()



class Project: 
    def __init__(self, thing: Union[Dict[str, Any], str, bytes], debug_trace: Optional[str] = None) -> None:
        def to_int(x):
            if isinstance(x, int): return x
            if isinstance(x, bytes): return int.from_bytes(x, 'big')
            if isinstance(x, str):
                if x.startswith("0x"):
                    return int(x, 16)
                try:
                    return int(x, 16)
                except ValueError:
                    return int(x)
            return int(x, 16)

        setup = {}

        if isinstance(thing, (str, bytes)):
            tx_hash = thing
            if isinstance(tx_hash, bytes):
                tx_hash = "0x" + tx_hash.hex()
            elif isinstance(tx_hash, str) and not tx_hash.startswith("0x"):
                tx_hash = "0x" + tx_hash

            tx = w3.eth.get_transaction(tx_hash)
            
            block_number = tx['blockNumber']
            block = w3.eth.get_block(block_number)
            
            setup = {
                "top_level_data": tx['input'], 
                "top_level_val": tx['value'],
                "from": tx['from'],
                "to": tx['to'], # could be None for the contract creation
                "block_number": block_number,
                "block_time": block['timestamp'],
                "debug_trace": debug_trace
            }
        elif isinstance(thing, dict):
            setup = setup_or_tx.copy()
            if debug_trace is not None:
                setup["debug_trace"] = debug_trace
        else:
            raise ValueError("setup_or_tx must be a transaction hash (str/bytes) or a setup dictionary")

        if isinstance(setup["top_level_data"], str):
            data_str = setup["top_level_data"]
            if data_str.startswith("0x"):
                data_str = data_str[2:]
            self.top_level_data: bytes = binascii.unhexlify(data_str) if data_str else b""
        else:
            self.top_level_data: bytes = setup["top_level_data"]

        self.top_level_val: int = to_int(setup["top_level_val"])
        self.top_level_caller: int = to_int(setup["from"])
        self.top_level_address: int = to_int(setup["to"])
        self.block_time: int = to_int(setup["block_time"])

        if "block_number" in setup and setup["block_number"] is not None:
            self.block_number: Optional[int] = to_int(setup["block_number"])
        else:
            self.block_number = None

        if not setup.get("top_level_code"):
            self.top_level_code = get_code_rpc(self.block_number, self.top_level_address)
            logger.info(f"Retrieved code for address {hex(self.top_level_address)} at block {self.block_number}, logged to {hex(self.top_level_address)}_{self.block_number}.bin")
            # with open(f"{hex(self.top_level_address)}_{self.block_number}.bin", "wb") as f:
            #     f.write(self.top_level_code)
        else:
            self.top_level_code = setup["top_level_code"]

        self.tx_origin: int = to_int(setup.get("origin", setup["from"]))
        self.debug_trace: Optional[str] = setup.get("debug_trace")
        self.debug_stack: List[Dict[str, Any]] = []

        if self.debug_trace is not None:
            self.set_debug_trace(self.debug_trace)

        initial_state = EVMState(tx_origin=self.tx_origin, block_time=self.block_time, block_number=self.block_number)
        
        initial_frame = Frame(
            code=self.top_level_code,
            calldata=self.top_level_data,
            address=self.top_level_address,
            caller=self.top_level_caller,
            value=self.top_level_val,
            is_static=False
        )
        initial_state.push_frame(initial_frame)

        self.simgr: SimulationManager = SimulationManager(initial_state, self)

    def set_debug_trace(self, debug_trace: str) -> None:
        self.debug_trace = debug_trace
        self.debug_stack = []
        
        if self.debug_trace.endswith('.gz'):
            opener = gzip.open(self.debug_trace, "rt", encoding="utf-8")
        else:
            opener = open(self.debug_trace, "r", encoding="utf-8")

        with opener as f:
            trace_data: str = f.read()

        lines: List[str] = trace_data.strip().splitlines()
        self.debug_stack = [json.loads(line) for line in lines]
        
        for item in self.debug_stack:
            if 'stack' not in item:
                item['stack'] = []

    def set_top_level_data(self, data):
        # todo: ugly ugly ugly, refactor
        self.top_level_data = data
        initial_state = EVMState(tx_origin=self.tx_origin, block_time=self.block_time, block_number=self.block_number)
        
        initial_frame = Frame(
            code=self.top_level_code,
            calldata=self.top_level_data,
            address=self.top_level_address,
            caller=self.top_level_caller,
            value=self.top_level_val,
            is_static=False
        )
        initial_state.push_frame(initial_frame)
        self.simgr: SimulationManager = SimulationManager(initial_state, self)



    def dump(self, filepath: str) -> None:
        setup = {
            "top_level_data": self.top_level_data.hex(),
            "top_level_val": hex(self.top_level_val),
            "from": hex(self.top_level_caller),
            "to": hex(self.top_level_address) if self.top_level_address else None,
            "block_number": self.block_number,
            "block_time": self.block_time,
            "origin": hex(self.tx_origin),
            "top_level_code": self.top_level_code.hex(),
            "debug_trace": self.debug_trace
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(setup, f, indent=4)