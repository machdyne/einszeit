# zetta (vendored)

The Zeitlos editor for text applications, from Zeitlos (`sw/common/zetta.c`,
`sw/common/zetta.h`), commit 40ef414e67e19b2bfe22e82d198065cc34fe8862
(2026-10-06). The code is unmodified; the copyright holder, Lone Dynamics
Corporation, has relicensed this copy under BSD-1-Clause (LICENSE.md), and
only the licence lines in the file headers differ from upstream.
Used by the terminal interface's Send screen (EZ-UI-001 §9).

Note for upstream: zetta_key() copies its input with memcpy() even when n is 0, so
NULL with n == 0 is undefined behaviour (UBSan stops on it). Einszeit passes a
valid empty buffer instead; a guard in zetta_key() would make NULL safe.
