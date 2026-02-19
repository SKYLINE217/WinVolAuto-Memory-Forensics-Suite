
import subprocess
import sys

try:
    # Try running the vol module
    result = subprocess.run([sys.executable, "-m", "volatility3.cli", "-h"], capture_output=True, text=True)
    if result.returncode != 0:
        # Try just 'vol' if installed in path
        result = subprocess.run(["vol", "-h"], capture_output=True, text=True)
    
    print("Return Code:", result.returncode)
    print("Output Head:")
    print(result.stdout[:1000])
    print("Output Tail:")
    print(result.stdout[-1000:])
except Exception as e:
    print(f"Error: {e}")
