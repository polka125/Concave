The project is under development, and is not production ready yet. Once it is tested, this note will be updated. 

Currently, a basic stepping and symbolic emulation implemented. However, now we rely on hardcoded memory values, which we get form REVM logs. 

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
