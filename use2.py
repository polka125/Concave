import web3
# for interacting with ENV 
import os
import json     

# retrieve json-rpc endpoint 

json_rpc_endpoint = os.getenv("WEB3_JSON_RPC", "http://localhost:8545")
w3 = web3.Web3(web3.HTTPProvider(json_rpc_endpoint))


res = w3.is_connected()


print(f"Connected to web3: {res}")  

# get the latest block number 
latest_block = w3.eth.block_number
print(f"Latest block number: {latest_block}")




req_block = latest_block - 100
# get the first transaction in the block 

# first_tx = w3.eth.get_transaction_by_block(req_block, 0)
# print(f"First tx: {first_tx}")


# getting storage of 0x8f753f2396fe86811f6f5aa068b302278a43c110 at 0x44eb83fe218cddcf2da3422795d427fe76c5b3ee7b70d6d5e794446e27767fba

addr = w3.to_checksum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
storage_value = w3.eth.get_storage_at(addr, 0x30a54bad9e3bdb835dff2aacf967123e66565a38618f19dda4c1fc941d4365a4, 25169233)
print(f"Storage value: {storage_value.hex()}")