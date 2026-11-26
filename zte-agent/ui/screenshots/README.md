# Responsive console previews

These PNGs are screenshots of the real console using fictional local fixtures. All network addresses, device names, MACs and profile identifiers are demonstration values. No live router, SMS, credentials, activation codes or private configuration was used. eSIM ICCIDs are masked in the rendered UI.

The ten previews cover the dashboard on phone and desktop, signal on tablet,
connected devices, eSIM, Wi-Fi Relay, Mihomo, Mihomo proxies and Tailscale.
The network pages use fictional SSIDs, profiles, proxy groups and tailnet data.
See the [gallery](../../../README.md#new-responsive-web-ui).

Regenerate all previews from the repository root with Playwright and Chrome
installed.

```sh
node scripts/test-agent.cjs screenshots
```

Pass one or more capture names to regenerate only those images.

```sh
node zte-agent/ui/tests/screenshots.cjs relay-desktop-dark tailscale-desktop-dark
```

See [Tests and QA](../../docs/README.md#tests-and-qa) for Playwright setup and `NODE_PATH`. The fixture listens on loopback only and never contacts a router.
