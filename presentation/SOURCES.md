# Incident sources and pitch scope

The deck uses historical incidents to explain speed versus trust, not to claim PatchMedic reproduced or would have prevented them.

- **event-stream (2018):** [npm's incident report](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident). A new maintainer added malicious flatmap-stream; the payload targeted Copay wallet software.
- **node-ipc (2022):** [GitHub-reviewed CVE-2022-23812](https://github.com/advisories/GHSA-97m3-w2cp-4xx6). Versions 10.1.1/10.1.2 contained maintainer-introduced file-overwrite behavior based on IP geolocation. Do not conflate this with every version or behavior of peacenotwar.
- **xz-utils (2024):** [Red Hat's March 29 alert](https://www.redhat.com/en/blog/urgent-security-alert-fedora-40-and-rawhide-users). Malicious injection in 5.6.0/5.6.1 tarballs intended to enable unauthorized access.
- **Log4Shell (2021):** [CISA's joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a). Active exploitation motivates urgency; it does not establish a universal hours-to-exploitation deadline or our own patching SLA.

## Defensible promise

**Patch with AI. Enforce with the kernel.** PatchMedic is a prototype autonomous security engineer for dependency updates. Four real AkashML passes assess and generate a small bounded repair. Semgrep scans incoming and generated source. yeet loads Linux eBPF LSM rules for configured protected files and connection destinations. The scoped broker holds real credentials. ClickHouse records collected results for review.

AI judgment and kernel enforcement are different decision points. A model's justification does not determine the kernel policy verdict on a configured operation. This does not establish an unchangeable complete jail, immunity to all backdoors, comprehensive filesystem protection, or an inability to ship malicious code. Current review stays local. No automated advisory watcher, every-CVE coverage, automatic publication or one-hour SLA is shipped.

## Demo wording

“This incoming update contains code to steal a key and send it away. Semgrep rejects it before execution. We then separately simulate those attack attempts under the same guard: Linux denies the protected read and external connection. Here is the model-generated repair, its scan and its passing tests.”

The fixture is inspired by the shape of supply-chain abuse, not a node-ipc/xz reproduction. The rejected postinstall is never executed. No claim is made that the live model was social-engineered into running it. The protected file is a teaching fixture, not a real SSH credential.
