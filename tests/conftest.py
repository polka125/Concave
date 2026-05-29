import json
import os

# This is the single source of truth for covered opcodes
COVERED_OPCODES = set()

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    trace_path = os.path.join("testdata", "concrete.json")
    if not os.path.exists(trace_path):
        return

    with open(trace_path, 'r') as f:
        all_opcodes = set(json.load(f).keys())

    covered = sorted(all_opcodes & COVERED_OPCODES)
    uncovered = sorted(all_opcodes - COVERED_OPCODES)

    terminalreporter.section("Opcode Coverage Report")
    if covered:
        terminalreporter.write_line(f"Covered opcodes ({len(covered)}): {', '.join(covered)}", green=True)
    else:
        terminalreporter.write_line("Covered opcodes (0): none", green=True)
    if uncovered:
        terminalreporter.write_line(f"Uncovered opcodes ({len(uncovered)}): {', '.join(uncovered)}", red=True)
    else:
        terminalreporter.write_line("All opcodes in concrete.json are covered!", green=True)