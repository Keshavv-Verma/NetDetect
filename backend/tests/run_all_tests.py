"""Central Test Suite Runner for NetDetect Backend.

Runs all 6 comprehensive test suites:
1. test_ml_integrity.py
2. test_feature_equivalence.py
3. test_pcap_validation.py
4. test_database.py
5. test_reporting_explanations.py
6. test_services.py
7. test_security_sanitization.py

Generates detailed test execution results and ML preservation verification.
"""

import sys
import time
import unittest
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def run_full_suite():
    print("=" * 80)
    print("NETDETECT CYBERSECURITY SUITE - BACKEND VERIFICATION & REGRESSION TESTS")
    print("=" * 80)
    start_time = time.time()

    loader = unittest.TestLoader()
    test_dir = Path(__file__).parent
    suite = loader.discover(start_dir=str(test_dir), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    elapsed = round(time.time() - start_time, 2)

    print("\n" + "=" * 80)
    print("TEST EXECUTION SUMMARY:")
    print(f"Total Tests Run   : {result.testsRun}")
    print(f"Failures          : {len(result.failures)}")
    print(f"Errors            : {len(result.errors)}")
    print(f"Skipped           : {len(result.skipped)}")
    print(f"Total Duration    : {elapsed}s")
    success = (len(result.failures) == 0 and len(result.errors) == 0)
    status_str = "SUCCESS (ALL TESTS PASSED)" if success else "FAILED"
    print(f"Overall Status    : {status_str}")
    print("=" * 80)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(run_full_suite())
