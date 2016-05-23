The Lua files set up a chain of wireshark dissectors for PTP over IP and Fuji X-T1 implementation of PTP over IP.
The dissectors are split up in dissectors that deal with the protocol (prefixed with 1\_) and  dissector that deals with MTP payloads (2\_mtp\_dissector.lua).
The load order is critical (2\_mtp\_dissector references header fields exposed from the 1\_ dissector at load time, so these need to be already loaded), and they are loaded in name order.

Put the dissector files in your plugin folder [1] ( ~/.wireshark/plugins on OS X,). 

References: [1] Wireshark Configuration Files and Folders [https://www.wireshark.org/docs/wsug\_html\_chunked/ChAppFilesConfigurationSection.html]