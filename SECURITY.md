# Reporting security issues

Please do not publish an exploit for the privileged helper before maintainers have had a reasonable opportunity to investigate. Reports should include platform, version, reproduction steps and whether elevated privileges are required.

KonsolLink must never request or store Discord credentials.

M0's local trust boundary is the UID selected by the root installer (plus root),
verified through kernel peer credentials. It does not authenticate one signed
application binary against other processes of the same user. Requests have a
closed schema; no shell, raw PF rule, sysctl name or caller-selected path is
accepted. The trial requires exclusive host-network management. See
[the implementation limits](docs/M0_IMPLEMENTATION.md) before running the root
helper. Physical PF/console qualification and signed distribution remain gates.
