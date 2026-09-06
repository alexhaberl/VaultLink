#!/usr/bin/env python3
"""Fail-closed coverage policy tests with missing and uninstrumented fixtures."""
import importlib.util
from pathlib import Path
import tempfile

path = Path(__file__).with_name("check-module-coverage.py")
spec = importlib.util.spec_from_file_location("coverage_check", path)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
policy = {"schema_version": 1, "modules": {module: {"lines": 50, "functions": 50} for module in checker.MODULES}}
with tempfile.TemporaryDirectory() as temporary:
    lcov = Path(temporary) / "coverage.lcov"
    blocks = [f"SF:/work/{module}\nDA:1,1\nDA:2,0\nFNDA:1,covered\nFNDA:0,uncovered\nLF:2\nLH:1\nFNF:2\nFNH:1\nend_of_record\n" for module in checker.MODULES]
    valid = "".join(blocks)
    lcov.write_text(valid)
    checker.verify(lcov, policy)
    for invalid in ["".join(blocks[1:]), valid.replace("LH:1", "LH:0"), valid.replace("FNH:1", "FNH:0")]:
        lcov.write_text(invalid)
        try:
            checker.verify(lcov, policy)
        except ValueError:
            pass
        else:
            raise AssertionError("coverage checker accepted missing or zero coverage")
    lcov.write_text(valid)
    policy["modules"][checker.MODULES[0]]["lines"] = 51
    try:
        checker.verify(lcov, policy)
    except ValueError:
        pass
    else:
        raise AssertionError("coverage checker accepted a local regression")
print("Module coverage negative fixtures passed")
