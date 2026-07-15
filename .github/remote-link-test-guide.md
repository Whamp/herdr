# Test remote link opening

This prerelease comes from the `Whamp/herdr` fork. It installs beside stable Herdr as `herdr-port-forward` and supports Linux and macOS.

## Install

Run this on the device where links should open. Replace `<ssh-target>` with any host accepted by your normal `ssh` command.

```bash
curl -fsSL https://github.com/Whamp/herdr/releases/download/remote-link-externalization-test/install-port-forward-test.sh \
  | sh -s -- --remote <ssh-target>
```

The installer downloads the matching local and remote artifacts, verifies their SHA-256 checksums, and installs them at `~/.local/bin/herdr-port-forward`. It does not replace `herdr`.

If `~/.local/bin` is not on your `PATH`, invoke the binary by its full path.

## Start an isolated test session

```bash
herdr-port-forward --remote <ssh-target> --session port-forward-test
```

The named session keeps the test server separate from the default Herdr session. Do not omit `--session port-forward-test` if the host already runs stable Herdr.

Open **Settings > Experiments** and enable **open remote links on this device**. Forwarding requires Herdr-managed SSH, which is enabled by default through `[remote].manage_ssh_config = true`.

## Check the behavior

1. Ctrl-click an ordinary HTTPS link. It should open in the initiating device's browser.
2. Start an HTTP server bound to `localhost` in a remote pane, then Ctrl-click its `http://localhost:<port>` link. One click should create the forward and open the page locally.
3. Attach a second client when possible. Only the client that clicked should open the link or display a failure notice.
4. Disable the experiment. Ordinary links should return to server-side opening, and attachment-owned forwards should be removed.

When reporting a problem, include both operating systems and architectures, `ssh -V`, and this output from each installed test binary:

```bash
herdr-port-forward status client --json
```

Do not include private URLs, credentials, hostnames, paths, queries, or browser history in public reports.

## Remove the test build

Stop the named remote server, then remove both aliases:

```bash
ssh <ssh-target> '~/.local/bin/herdr-port-forward --session port-forward-test server stop'
rm -f ~/.local/bin/herdr-port-forward
ssh <ssh-target> 'rm -f ~/.local/bin/herdr-port-forward'
```

Disable **open remote links on this device** if you do not want the device-local experiment enabled for later builds. Stable Herdr remains installed and unchanged.
