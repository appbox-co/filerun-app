# php7.4 patches

Each `*.patch` file here is added to Ubuntu's php7.4 quilt series in name
order, so prefix them with a number (`0001-...`). Patches must apply to the
`php7.4-7.4.3` source tree (Ubuntu 7.4.3-4ubuntu2.29) with `-p1`; the build
fails if one does not. The build records the name and SHA-256 of every
applied patch in `/usr/share/appbox/php74-patches.sha256`, and the release
gate compares that list with this directory.

Bump `PHP74_LOCAL_SUFFIX` in the Dockerfile (`+cylo2`, `+cylo3`, ...) whenever
the set of patches changes after a release has been pushed, and add a
regression check under `release/regression/` for the issue each patch fixes.
`+cylo1` was carried by the unpatched staging trial builds, so the first
patched release used `+cylo2` (2022.05.19-2, patch 0001 only) and the
2022.05.19-3 release, with patches 0001-0009, uses `+cylo3`. The gate
refuses suffixes that were already released with another patch set
(`released_suffixes`). The gate keeps a list of such suffixes
(`unpatched_suffixes` in `release/verify-image.sh`): release and candidate
runs refuse them, and a trial run without patches must use one.
A release or candidate gate run refuses to pass while this directory has no
patches or `release/regression/` has no checks.

## Patches

- `0001-CVE-2026-109618-109619.patch`: the 21 October 2026 fix for
  GHSA-w8hw-w9fx-j79w (CVE-2026-109618, RCE via OOM corruption during
  multipart parsing) and GHSA-6wmf-4rv5-p3rp (CVE-2026-109619, RCE via stale
  global state). It ports the minimal mitigation php-src published for
  end-of-life branches (1d7dec178a0, reduced from 01a40e89fbfc on PHP-8.2),
  as Canonical shipped it for php8.1 8.1.2-1ubuntu2.28. Its DEP-3 header maps
  every 8.1 hunk to 7.4.3, including the ones that do not apply.
  `Zend/zend_vm_execute.h` in the patch is `Zend/zend_vm_gen.php` output for
  the patched `Zend/zend_vm_def.h`. Checks: `release/regression/cve-2026-*.sh`.

  Behaviour changes: memory exhaustion ends the PHP process (an FPM worker
  exits with status 1, the client gets no response, and shutdown functions
  and destructors do not run; the message is in the FPM log), and
  `session.upload_progress.enabled` no longer has any effect.

The 19 November 2026 php-src advisories (fixed upstream in 8.2.36, 8.3.37,
8.4.28 and 8.5.13) are backported from their PHP-8.2 fix commits. Each patch
header maps its hunks to 7.4.3 and names the upstream commit; the phpt tests
are replaced by checks in `release/regression/`.

- `0002-CVE-2026-129289-fpm-unread-body.patch`: GHSA-qc49-hpvq-g2w6, FPM
  request smuggling through an unread request body (28014fd092).
  Exploitable only behind a front end that keeps FastCGI connections open,
  which our nginx config does not, but customers can edit it.
- `0003-CVE-2026-126714-session-file-truncate.patch`: GHSA-fm2m-fjf5-v3cp,
  session files are always truncated before a write (41c0941ae2).
- `0004-CVE-2026-129496-error-log-timezone.patch`: GHSA-gr4f-wgx5-jpfv,
  timezone cache use-after-free via early error_log timestamps
  (f986c5ca37). Error-log lines written before a request starts are now
  stamped in UTC.
- `0005-CVE-2026-128064-https-scheme-case.patch`: GHSA-f6gg-rchx-xw8j,
  HTTPS:// and FTPS:// URLs use TLS regardless of case (cb68a63e81).
- `0006-CVE-2026-129538-cgi-path-info.patch`: GHSA-5j3f-64r7-f564, php-cgi
  PATH_INFO underflow (964cdcfa5a). php-cgi is installed but not used.
- `0007-CVE-2026-15353-129506-soap.patch`: GHSA-q23r-hr55-xmpg and
  GHSA-4646-p932-gw34, SOAP arraySize out-of-bounds read and DTD
  use-after-free (59e46404a7, 66db5cda7d).
- `0008-CVE-2026-128090-phar-signature.patch`: GHSA-68fq-fh7h-f8gr, keyless
  phar signatures are refused when an OpenSSL public key is present
  (7050cf3380).
- `0009-CVE-2026-127960-folded-headers.patch`: GHSA-mmf9-xm3v-hg2x,
  quadratic folded response headers in the HTTP wrapper (a303f69726).
  Ubuntu's 7.4.3-4ubuntu2.29 carries the CVE-2025-1217 header folding that
  introduced it.

Not backported: GHSA-658j-r8rw-q6mx (CVE-2026-115560, session serializer
mismatch through upload progress) needs session upload progress, which
patch 0001 already disables; GHSA-3mg3-cr28-46gc (CVE-2026-129292, FPM
status page XSS) because 7.4's fpm_status.c differs and the image enables
no status page; GHSA-jm4m-qfqx-967m (CVE-2026-129291) because the advisory
limits it to 8.2.7 and later; and the 8.3+/8.4+/8.5-only issues, whose code
7.4 does not have.
