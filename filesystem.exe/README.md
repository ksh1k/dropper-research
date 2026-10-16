\# Dropper



\## Version 1.0

\* Drops and launches plain executable files.



\## Version 2.0

\* Encodes payloads using XOR and/or Base64.

\* Launches injected DLLs.

\* Drops random-named files.



\## Version 3.0

\* Project converted to DLL.

\* Dead-imports converted into dead-exports.

\* Most static imports converted to dynamic imports.



\## Version 4.0

\* Three-IP scheme to distinguish analysis type.

\* `PRIMARY\_IP`: plain string embedded in binary.

\* `ENCODED\_IP`: obfuscated real connection, decoded at runtime via XOR.

\* `ENCODED\_IP2`: obfuscated secondary endpoint, decoded at runtime via XOR, no connection.

\* `automate.py` accepts `--ip1 --ip2 --ip3` to set all three IPs at compile time.

