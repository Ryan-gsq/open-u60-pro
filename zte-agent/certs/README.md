# Operator server certificates

The operators' SM-DP+ servers use TLS certificates issued by the GSMA eSIM root CI, not by a web CA. zte-agent embeds the roots in this directory (`include_str!` in `src/esim_native.rs`) and trusts only them for ES9+ requests (downloads and receipts); the system CA store is not used.

`gsma-rsp2-root-ci1.pem` is "GSM Association - RSP2 Root CI1" (valid 2017–2052, SHA-256 fingerprint `5E:3E:91:FD:45:43:27:C3:AF:5D:32:A7:A7:3B:BC:59:FE:43:AA:7D:85:FD:32:D5:DB:44:42:3F:80:A5:6B:B3`). The SHA-1 of its public key, `81370f5125d0b1d408d4c3b232e6d25e795bebfb`, matches the CI key ID that the tested card lists in `chip info` (`euiccCiPKIdListForVerification`), so it is the root the card itself trusts. A unit test checks the embedded key ID. Add a root here only if a card lists its key ID.
