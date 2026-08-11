# Security policy

## Supported version

Security fixes are made on the latest release and `main`. Older alpha releases are not
maintained unless a release note says otherwise.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use GitHub's private
**Report a vulnerability** form in the repository Security tab:

<https://github.com/taipei49314/unasked/security/advisories/new>

Include the affected version or commit, platform, minimal reproduction, impact, and any
suggested mitigation. Remove credentials, private repository contents, benchmark cases, and
other sensitive data before submitting. You should receive an acknowledgement within seven
calendar days and a status update within fourteen days. These targets are not a bug-bounty
or disclosure-deadline commitment.

Please allow time for a fix and coordinated disclosure before publishing details. If the
private form is unavailable, open a public issue containing only a request for a confidential
contact channel and no vulnerability details.

## Security boundary

UNASKED treats observed repositories and model/provider output as untrusted. The local
executor is deliberately restricted, but it is not an OS sandbox and does not prove network,
filesystem, process, or secret isolation. Do not treat local replay as a security boundary.
The complete assumptions and residual risks are documented in
[`unasked-threat-model.md`](unasked-threat-model.md).

No release, issue response, or vulnerability fix authorizes an M0 research claim.
