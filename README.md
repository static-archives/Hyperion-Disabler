# The Hyperion Disabler
A complete "full-fledged" bypass for hyperion that I wrote because I was bored :p
<br>
But no really, this completely disables the integrity checker by redirecting execution flow at every point in hash generation.<br>
It then modifies the hash to essentially cloak every edit we make.<br>
It then hooks the instrumentation callback, rendering hyperion defenseless. It spoofs every call to ntqueryvirtualmemory to host a secure RWX page 10000000h bytes in size, enough for any practical DLL injection<br>
<br>
It then allows you to modify tls callbacks, hook every syscall, and it even contains a full bypass for hardware breakpoints.
<br>
