
import binascii
import pdb
import sys
import claripy


from src.concave import Project
from src.concave import get_slice

setup_4 = {
    "code_file": "logs/4.txt",
    "top_level_code": None,
    "top_level_data": binascii.unhexlify("7ce2914200000000000000000000000000000000000000000000000055de6a779bbac000000000000000000000000000ed643618dd5194f243a8f23c7bd786a37a6dcf8b000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000002b9a63501617dd26b6"),
    "top_level_val": 0,
    "from": binascii.unhexlify("ED7cFbB8CACA87cE8EA6b4BF33288379C70b5210"),
    "to": int("42D0ba0223700DEa8BCA7983cc4bf0e000DEE772", 16),
    "block_time": 0x5f65536b, 
    "debug_trace": "logs/4.json",
    "debug_stack": None  
}


def bvv_from_str(s: str) -> claripy.ast.bv.BV:
    return claripy.BVV(int(s, 16), len(s) * 4)


setup = setup_4

data = setup["top_level_data"]

data_len = len(setup["top_level_data"]) * 8

symbolic_data = claripy.BVS("input_data", data_len)

pt1 = bvv_from_str("7ce2914200000000000000000000000000000000000000000000000055de6a77")
pt2 = claripy.BVS("pt2", len("9bbac") * 4)
# pt3 = claripy.BVS("pt3", len("000000000000000000000000000ed643618dd5194f243a8f23c7bd786a37a6dcf8b") * 4)
pt3 = bvv_from_str("000000000000000000000000000ed643618dd5194f243a8f23c7bd786a37a6dcf8b")
pt4 = bvv_from_str("000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000002b9")
pt5 = claripy.BVS("pt5", len("a63501617dd26b6") * 4)

res = pt1
res = res.concat(pt2)
res = res.concat(pt3)
res = res.concat(pt4)
res = res.concat(pt5)

# https://etherscan.io/tx/0x1fbd5603f31db5f6aadab58721efc4aed89ba8fa12a937bdea8b435ef32e6623
res = bvv_from_str("489c6d7f0000000000000000000000007ef1081ecc8b5b5b130656a41d4ce4f89dbbcc8c000000000000000000000000bc6b3dc17e86c8cacf0f384f2e19468c36154a22")

print(len(data) * 8)
print(res.length)

print(f"Symbolic data: {res}")
print(f"Symbolic slice: {get_slice(res, 0, 32)}")

# print(binascii.hexlify(get_slice(data, 0, 32)).decode())
# print(binascii.hexlify(get_slice(res, 0, 32)).decode())

# sys.exit(0)

setup["top_level_data"] = res


p = Project(setup)


# while p.simgr.active:

while len(p.simgr.active) > 0:
    p.simgr.step()
    print(f"Active states: {len(p.simgr.active)}")
    print(f"Finished states: {len(p.simgr.finished)}")
    print()
