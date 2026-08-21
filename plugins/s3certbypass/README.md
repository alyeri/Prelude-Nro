# Splatoon 3 certificate bypass

This Skyline plugin patches only Splatoon 3's certificate-chain result at
runtime. It does not patch peer-name validation, relay behavior, or clocks.

The scanner is intentionally fail-closed: it requires exactly one signature
match, validates the target AArch64 instruction, writes one 32-bit instruction,
and verifies the result. Runtime diagnostics are appended to:

`sd:/atmosphere/contents/0100C2500FC20000/s3certbypass.log`

If the log is absent after launching the game, the custom Skyline loader did not
reach logger initialization. If the loader starts but the plugin refuses a new
game build, the log contains the specific signature/validation error.
