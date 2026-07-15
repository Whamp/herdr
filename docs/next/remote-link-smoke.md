# Remote link externalization smoke

**Status: EXECUTED — PASS**

The laptop-to-desktop smoke ran on 2026-07-15 over the existing private-network SSH route. It used the pinned candidate, a uniquely named Herdr session, temporary device-local configuration, high ephemeral loopback ports, recording openers and services, and a second isolated full client. Stable Herdr processes and configuration remained untouched.

Two setup mistakes were corrected before the final counted observations: an initial manual launcher overrode the laptop's GUI runtime directory, preventing Chromium from finding its Wayland socket, and an initial `localhost` service listened only on IPv4. Neither was treated as a product result. The final run preserved the real GUI runtime and provided matching remote IPv4 and IPv6 loopback services.

## Results

| Assertion | Result | Evidence |
| --- | --- | --- |
| Disabled fallback | Pass | With the experiment disabled, one modified click invoked only the existing server-side opener. Neither laptop client received an opener call and no forward command ran. |
| Ordinary client-local opening | Pass | With the experiment enabled, an ordinary link invoked only the initiating laptop opener. The server fallback count and second-client opener count did not change. |
| Same-port forwarding | Pass | A numeric-loopback link created one exact loopback listener at the preferred port, rewrote no other URL component, and carried a request to the intended remote service. |
| Collision remap | Pass | A held preferred endpoint forced one fallback candidate. Herdr opened a different explicit loopback-only port and traffic reached the intended remote service while the collision holder remained active. |
| Ready reuse | Pass | Reopening the collision destination reused the same local port, produced one new opener call, and issued no additional SSH forward command. |
| Independent destination | Pass | A second destination created exactly one separate mapping while the prior mappings remained live and isolated. |
| Second-client isolation | Pass | A simultaneously attached second full client received no opener call, source-local failure notice, or forwarding side effect from the initiating client's actions. |
| URL-free failure feedback | Pass | A controlled opener rejection produced exactly the approved URL-free source-local banner on the initiating client and no banner on the second client. No fallback or extra forward ran. |
| One-click browser result | Pass | In the final clean interactive run, one Ctrl-click created both `localhost` loopback listeners, opened a new laptop browser tab, and loaded the page from the remote dual-stack loopback service. |
| Listener removal after disconnect | Pass | Normal detach removed every temporary IPv4 and IPv6 forwarding listener checked across the manual run. |

## Isolated procedure

1. From the laptop, confirm the remote device is visible through the existing private network and that non-interactive SSH succeeds. Stop after a short bounded retry if either check fails.
2. Build the candidate with the pinned toolchain. Use temporary config, state, log, SSH-control, and browser-recording paths while preserving the laptop's real GUI runtime directory. Start a uniquely named temporary Herdr session from the laptop targeting the desktop. Do not reuse a normal Herdr session or config.
3. Start recording HTTP services on distinct high-numbered remote loopback endpoints. Serve `localhost` checks on both IPv4 and IPv6. Reserve one preferred local endpoint to force a collision. Record requests without retaining URLs or headers.
4. With the experiment disabled, use the production modified-link input and verify only the existing server-side fallback runs.
5. Enable **open remote links on this device**. Verify an ordinary link opens only on the initiating laptop.
6. Exercise same-port forwarding, forced collision remapping, Ready reuse, and an independent destination. Verify exact loopback listeners, bounded SSH-forward command counts, and traffic to only the intended recording service.
7. Keep a second full client attached. Verify source identity, opener calls, and notices remain isolated.
8. Trigger one controlled terminal failure and verify the exact URL-free diagnostic category only on the initiating client.
9. Perform a final clean Ctrl-click against a fresh dual-stack `localhost` destination and verify the browser tab opens directly on the laptop with the remote response.
10. Detach normally. Verify all owned listeners disappear, then stop temporary services and the named session and remove every temporary path.

Cleanup passed. The named candidate server, candidate clients, temporary browser-opener instrumentation, HTTP services, binaries, discovery wrapper, listeners, and laptop/desktop temporary trees were removed. The pre-existing stable server and remote bridge retained the same process identities before and after cleanup.
