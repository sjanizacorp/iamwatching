#!/usr/bin/env bash
# IamWatching diagnostic — run this if cloud selection seems wrong
set -euo pipefail

echo "=== IamWatching Diagnostic ==="
echo ""

# Which iamwatching binary runs?
echo "Binary location:"
which iamwatching 2>/dev/null || echo "  NOT FOUND in PATH"
echo ""

# Which Python file backs it?
echo "CLI source file:"
python3 -c "
import importlib.util
spec = importlib.util.find_spec('iamwatching.cli.main')
print(' ', spec.origin if spec else 'NOT INSTALLED')
" 2>/dev/null || echo "  Package not importable"
echo ""

# Version check
echo "Version:"
python3 -c "
import importlib.metadata
try:
    print(' ', importlib.metadata.version('iamwatching'))
except:
    print('  Unknown')
" 2>/dev/null
echo ""

# Check the fix is present
echo "Cloud routing fix present:"
python3 -c "
try:
    import iamwatching.patterns.matcher as m
    src = open(m.__file__).read()
    print('  _rule_cloud_map:', '_rule_cloud_map' in src)
    print('  _active_clouds:', '_active_clouds' in src)
    print('  scan_start_ms in run_all:', 'scan_start_ms' in src)
except Exception as e:
    print('  ERROR:', e)
" 2>/dev/null
echo ""

echo "Importer scan_start_ms present:"
python3 -c "
try:
    import iamwatching.graph.importer as m
    src = open(m.__file__).read()
    print('  scan_start_ms = \$ssm:', src.count('scan_start_ms = \$ssm'), 'occurrences (need 6)')
except Exception as e:
    print('  ERROR:', e)
" 2>/dev/null
echo ""

# Test the cloud flag logic
echo "Cloud flag simulation:"
python3 -c "
import sys
sys.argv = ['iamwatching', 'audit', '--gcp']
# Just check what _build_cloud_framework_filter returns
from iamwatching.cli.main import _build_cloud_framework_filter
result = _build_cloud_framework_filter(do_aws=False, do_azure=False, do_gcp=True, explicit_family=None)
print('  --gcp filter:', result)
cis_would_run = any('CIS' in x for x in result)
print('  CIS-AWS would run during --gcp:', cis_would_run, '(should be False)')
" 2>/dev/null

echo ""
echo "=== End Diagnostic ==="
