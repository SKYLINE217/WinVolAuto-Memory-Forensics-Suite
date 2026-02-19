
import volatility3.cli
print(dir(volatility3.cli))
if hasattr(volatility3.cli, 'main'):
    print("Found main() in volatility3.cli")
elif hasattr(volatility3.cli, 'run'):
    print("Found run() in volatility3.cli")
