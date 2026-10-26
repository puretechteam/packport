# Security

packport reads and extracts archives that come from anywhere, so an archive that makes it write outside the destination folder, create links, hang, or use unbounded memory is a security bug. So is output that makes other tools misbehave.

## Reporting

Please don't open a public issue. Use **Security → Report a vulnerability** on this repository's GitHub page, which only the maintainers can see. Include the archive that triggers it, if you can.

You'll get a reply within a week. Fixes ship in a new release, and the changelog credits you unless you'd rather it didn't.

## Supported versions

Only the latest release gets fixes.
