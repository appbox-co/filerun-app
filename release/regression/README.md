# Regression checks

Each `*.sh` file here is mounted read-only into the image at
`/release/regression/` and run with `sh`, without network access. It must
exit 0 only when the issue it covers is fixed. Add one for every patch in
`php74-patches/`. `php7.4`, `php-fpm7.4` and `curl` are available in the image.

`lib/` holds shared helpers and is not run directly. `lib/fpm.sh` starts a
private php-fpm7.4 master with a single static worker on 127.0.0.1, so
consecutive requests reach the same process, and `lib/fcgi.php` sends
FastCGI requests to it the way nginx does.

| Check | Patch |
| --- | --- |
| `cve-2026-109618-oom.sh` | `0001-CVE-2026-109618-109619.patch` (out-of-memory handling, multipart headers, request variable arrays) |
| `cve-2026-109619-state.sh` | `0001-CVE-2026-109618-109619.patch` (state reset, session upload progress) |
| `cve-2026-129289-fpm-unread-body.sh` | `0002-CVE-2026-129289-fpm-unread-body.patch` (uses `lib/keepconn.php`) |
| `cve-2026-126714-session-file.sh` | `0003-CVE-2026-126714-session-file-truncate.patch` |
| `cve-2026-129496-error-log-timezone.sh` | `0004-CVE-2026-129496-error-log-timezone.patch` |
| `cve-2026-128064-https-scheme-case.sh` | `0005-CVE-2026-128064-https-scheme-case.patch` |
| `cve-2026-129538-cgi-path-info.sh` | `0006-CVE-2026-129538-cgi-path-info.patch` |
| `cve-2026-15353-129506-soap.sh` | `0007-CVE-2026-15353-129506-soap.patch` (memory-safety: may also pass on an unpatched build) |
| `cve-2026-128090-phar-signature.sh` | `0008-CVE-2026-128090-phar-signature.patch` |
| `cve-2026-127960-folded-headers.sh` | `0009-CVE-2026-127960-folded-headers.patch` |
