
import os
import volatility3
print(f"Volatility3 location: {os.path.dirname(volatility3.__file__)}")

# List contents of volatility3 directory
vol_dir = os.path.dirname(volatility3.__file__)
print(f"Contents of {vol_dir}:")
for f in os.listdir(vol_dir):
    print(f"  {f}")

# Check cli directory
cli_dir = os.path.join(vol_dir, "cli")
if os.path.exists(cli_dir):
    print(f"Contents of {cli_dir}:")
    for f in os.listdir(cli_dir):
        print(f"  {f}")
