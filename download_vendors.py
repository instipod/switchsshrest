#!python
from mac_vendor_lookup import MacLookup, BaseMacLookup

BaseMacLookup.cache_path = "vendors.txt"
mac_lookup = MacLookup()

mac_lookup.update_vendors()