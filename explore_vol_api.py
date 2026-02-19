
import sys
import os
import inspect
from volatility3.framework import contexts, automagic, plugin_runner
from volatility3.framework import plugins
from volatility3 import plugins as vol_plugins

# Try to list plugins
print("Attempting to list plugins...")

try:
    # This is a common way to discover plugins in Vol3
    from volatility3.framework import import_files
    from volatility3.plugins import windows, linux, mac
    
    # Just listing attributes of the windows module for now
    print("Windows plugins found via module inspection:")
    for name, obj in inspect.getmembers(windows):
        if inspect.ismodule(obj):
            print(f"  Category/Module: {name}")
            for subname, subobj in inspect.getmembers(obj):
                if inspect.isclass(subobj) and subname != "PluginInterface" and "Plugin" in str(subobj.__mro__):
                     print(f"    Plugin: {subname}")
        elif inspect.isclass(obj) and "Plugin" in str(obj.__mro__):
            print(f"  Plugin: {name}")

except Exception as e:
    print(f"Error: {e}")

print("-" * 20)
print("Checking CLI help output approach:")
import subprocess
try:
    # Running vol -h to see how it lists plugins
    result = subprocess.run(["vol", "-h"], capture_output=True, text=True)
    print(result.stdout[:500]) # First 500 chars
except Exception as e:
    print(f"CLI Error: {e}")
