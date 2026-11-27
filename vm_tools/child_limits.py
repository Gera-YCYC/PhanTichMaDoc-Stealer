"""Linux subprocess entrypoint for fixed trusted tools, not an endpoint for the model."""
import os
import resource
import sys

if len(sys.argv) < 3 or not os.path.isabs(sys.argv[2]):
    raise SystemExit("Expected bounded address space and absolute trusted executable")
address_space = int(sys.argv[1])
if not 1_500_000_000 <= address_space <= 4_000_000_000:
    raise SystemExit('Unsupported address-space limit')
resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
resource.setrlimit(resource.RLIMIT_CPU, (85, 90))
resource.setrlimit(resource.RLIMIT_FSIZE, (70_000_000, 70_000_000))
resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execv(sys.argv[2], sys.argv[2:])
