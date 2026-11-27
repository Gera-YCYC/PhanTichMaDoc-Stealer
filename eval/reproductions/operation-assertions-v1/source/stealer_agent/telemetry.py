"""OS process measurements; peaks belong to this process, not the whole machine."""
import os
import sys


def available_memory_bytes():
    """Machine-wide available RAM at this instant, not an inferred peak."""
    try:
        if os.name=='nt':
            import ctypes
            from ctypes import wintypes
            class Status(ctypes.Structure):
                _fields_=[('length',wintypes.DWORD),('load',wintypes.DWORD)]+[
                    (n,ctypes.c_ulonglong) for n in ('total_physical','available_physical','total_pagefile',
                    'available_pagefile','total_virtual','available_virtual','extended_virtual')]
            status=Status();status.length=ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.available_physical
        elif sys.platform.startswith('linux'):
            from pathlib import Path
            for line in Path('/proc/meminfo').read_text().splitlines():
                if line.startswith('MemAvailable:'): return int(line.split()[1])*1024
    except (OSError,ValueError,AttributeError,IndexError):
        pass
    return None


def process_memory():
    values = {"host_rss_bytes": None, "host_peak_rss_bytes": None}
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            class Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in (
                        "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                        "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                        "PagefileUsage", "PeakPagefileUsage")]
            stats = Counters()
            stats.cb = ctypes.sizeof(stats)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            fn = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
            fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            if fn(kernel.GetCurrentProcess(), ctypes.byref(stats), stats.cb):
                values.update(host_rss_bytes=stats.WorkingSetSize, host_peak_rss_bytes=stats.PeakWorkingSetSize)
        elif sys.platform.startswith('linux'):
            from pathlib import Path
            # Read current RSS and high-water RSS from one proc status snapshot.
            # Mixing an earlier getrusage peak with a later statm RSS can race
            # with allocations performed while collecting the measurement.
            fields = {line.partition(':')[0]: line.partition(':')[2].split()
                      for line in Path('/proc/self/status').read_text().splitlines()}
            current, peak = fields['VmRSS'], fields['VmHWM']
            if current[1] == peak[1] == 'kB':
                values.update(host_rss_bytes=int(current[0]) * 1024,
                              host_peak_rss_bytes=int(peak[0]) * 1024)
    except (OSError, ValueError, IndexError, AttributeError, KeyError):
        pass
    return values
