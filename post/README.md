# Custom Post modules

## Hivedump

- This is an implementation of the HiveNightmare exploit into Metasploit
- This module looks for Shadow Copies of Windows and copies the SAM files from that Shadow copy
- Then it downloads those SAM files and run secretsdump on them in order to get the user hashes
- It will also delete any remaining copies from the machines

**NOTE: This is mainly for testing and not for stealth**
