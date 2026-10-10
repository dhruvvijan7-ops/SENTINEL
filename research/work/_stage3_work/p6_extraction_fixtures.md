## 10. Safe Archive Extraction Design

Extraction is the one operation in Sentinel that turns a bounded input into
an unbounded one, so it gets a normative algorithm rather than advice. The
algorithm applies to every container: ZIP, TAR, 7z, RAR, ISO, CAB, OOXML,
OLE, and every nested container discovered by recursion.

### 10.1 The algorithm

```
EXTRACT(root_artifact, ctx):
  1.  LIST   container.list()                      # central directory / header only; no bytes written
        -> members[] (path, size_compressed, size_uncompressed, method,
                      is_directory, is_symlink, link_target, encrypted, crc32)
        if LIST fails at offset 0: emit status=corrupted; RETURN
        if container declares truncation: emit status=truncated (§2.4); continue with what exists

  2.  BUDGET init(root_artifact):
        remaining_bytes   = ctx.max_materialised_bytes
        remaining_nodes   = ctx.max_nodes
        remaining_time    = ctx.max_wall_clock
        seen_hashes       = {}                       # cycle + shared-subtree protection (§6.3)

  3.  for each member in members (in central-directory order):
        if deadline exceeded or budgets exhausted:
              close graph; status=resource_limit_exhausted; BREAK

        3a. SANITISE(member.path) -> safe_rel      # §10.2, MUST succeed or member is dropped
              if sanitisation rejected the path:
                  emit archive_member fact with rejection_reason;
                  continue                          # the member is NOT an error; it is a fact

        3b. target = quarantine_root / root_artifact.sha256 / safe_rel

        3c. CONTAIN(target, quarantine_root)        # §10.3, ancestry check
              if violated: emit rejection_reason=path_escape; continue

        3d. if member.is_symlink or member.is_hardlink:
                validate link_target with the same SANITISE rules
                  (absolute targets, targets escaping, device targets -> reject)
                NEVER create the link itself in the default build;
                record the validated target as a fact only.     # §10.5

        3e. declared = member.size_uncompressed
            if declared > ctx.max_node_bytes:          emit reason=size_limit; continue
            if member.size_uncompressed / max(1, member.size_compressed)
                 > ctx.max_compression_ratio:          emit reason=ratio_limit; continue
            if remaining_bytes <= 0:                   emit reason=budget; continue

        3f. write target with O_CREAT|O_EXCL, mode 0o600, in a directory the
            worker created and owns; stream-copy with a RUNNING COUNT:
                written = 0
                for chunk in member.stream():
                    written += len(chunk)
                    if written > ctx.max_node_bytes:            ABORT; unlink; reason=size_limit
                    if written > declared * 1 + slack:          ABORT; unlink; reason=lie_about_size
                    remaining_bytes -= len(chunk)
                    if remaining_bytes < 0:                     ABORT; unlink; reason=budget
                    if deadline exceeded:                       ABORT; unlink; reason=timeout
                    out.write(chunk)
            if member.crc32 is declared and crc32(actual) != declared:
                keep the bytes, emit reason=crc_mismatch, flag node as untrusted-content

        3g. hash = sha256(target)
            if hash in seen_hashes:
                emit edge same_bytes_as to the existing node; continue (do not re-expand)
            seen_hashes[hash] = node

        3g. IDENTIFY(target)                          # §2, from the store, not from the extension
            RECURSE EXTRACT(target, ctx) if:
                depth < ctx.max_depth
                AND identification.selected is a container family
                AND the family is enabled for recursion (§10.4)

  4.  FINALISE: every member, extracted or not, has produced an archive_member
      fact and (if the family maps) a canonical archive_member event.
      Parent status = analysed/partial per §8.2.
```

### 10.2 Path sanitisation (normative)

Applied to *every* member path before it is joined to anything. Evidence for
the Windows rules: UP-MSNAME.

| Step | Rule | On failure |
|---|---|---|
| P1 | Reject empty paths and paths that are only `.` / `..` | drop |
| P2 | Normalise separators: `\` → `/`; reject paths containing a NUL byte | drop |
| P3 | Reject absolute paths (leading `/`), drive-relative (`C:x`), drive-absolute (`C:/`), and UNC (`//host/`, `\\host\`) | drop |
| P4 | Reject Windows device namespaces: `//./`, `//?/`, `\\.\`, `\\?\`, and any component equal to `CONIN$` / `CONOUT$` | drop |
| P5 | Resolve `.` and `..` **lexically, on the normalised string** — never by filesystem resolution. If the result starts with `..`, the path escapes and is dropped | drop |
| P6 | Split into components; reject any component that is empty, `.`/`..`, longer than 255 bytes, ends with a space or a period, or whose stem case-insensitively equals a reserved device name (CON/PRN/AUX/NUL/COM1–9/LPT1–9 plus the ISO-8859-1 superscript forms) | drop that component (and therefore the member) |
| P7 | Reject any component containing `:` (an ADS or drive separator) | drop |
| P8 | Reject if the joined path would exceed 4,096 bytes, or the depth exceeds 32 components (`PROPOSED - TO BENCHMARK`) | drop |
| P9 | Unicode-normalise to NFC for comparison and storage; keep the original bytes as `archive_member.member_path_original` | — |
| P10 | Final result must be a relative POSIX-style path with no empty components | drop |

P5 is the crux. A lexical resolution cannot be tricked by a symlink that
exists on the extraction filesystem, because nothing has been created yet at
the time the check runs — and §10.3 makes sure the write target's *real*
ancestry is still inside the quarantine root afterwards, so even if something
else races the directory, the write fails closed.

### 10.3 Ancestry containment (normative)

After sanitisation and immediately before opening the target, the worker
computes the *real* path of every ancestor of the target and asserts that the
quarantine root's real path is a prefix of it, component-wise (not
string-wise: `/q/abc` must not be accepted as a prefix of `/q/abcd`). This
catches the case where a previously extracted member created a symlink that a
later member would traverse — which is why, in the default build, §10.5
prevents symlink creation outright.

```
assert_containment(target, root):
    root_real = realpath(root)                       # root was created by this worker, mode 0o700
    cur = dirname(target)
    while cur is not root_real and cur != dirname(cur):
        if not is_within(realpath(cur), root_real):   # component-wise
            raise PathEscape
        cur = dirname(cur)
    assert is_within(realpath(dirname(target)), root_real)
```

Additionally, the target is opened with `O_NOFOLLOW` semantics (Python:
`os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW)`), so a
component that became a symlink between the check and the open fails the
open rather than writing through it.

### 10.4 Recursion policy

Recursion is enabled per family and is the reason the depth limit exists:

| Parent family | Recurses into | Default |
|---|---|---|
| ZIP / TAR / 7z / RAR / ISO / CAB | any container family | on, depth 8 |
| OOXML | ZIP members, and OLE members of embedded objects | on, depth 8 (OOXML counts as one level) |
| OLE2 | embedded ZIP/OLE objects | on, depth 8 |
| PDF | embedded files (`/EmbeddedFile` streams) | on, depth 8 |
| PE | overlay carving, resources of type RCDATA/manifest containing XML | on, depth 4 (`PROPOSED - TO BENCHMARK`) |
| LNK | **never** — a LNK points outside itself; `references` only | off |
| image | appended ZIP (polyglot) | on, depth 2 |
| disk image / VHD / VMDK | **never** (§9: mounting executes a filesystem driver) | off |
| NSIS / Inno | **never** in Stage 3 (Q3-016) | off |

`unblob` and `binwalk` (§5.8) are *not* recursion targets; if an operator
enables them they run as a bounded enrichment step on leaf artifacts that no
family parser claimed, under the same budgets.

### 10.5 Symlinks, hardlinks, device nodes, setuid

The default build **never creates** a symlink, hardlink, FIFO, device node or
socket from an archive, regardless of what the container declares. Instead it
validates and records the declared target as a fact
(`archive.member.is_symlink`, `.link_target`). This is a stricter rule than
Python's own `data_filter` (ARC-TARFILE, which refuses absolute and
outside-destination link targets but does allow in-destination links), and it
is chosen because an in-destination link is still enough to defeat a naive
containment check in a later recursion step. Setuid/setgid/sticky bits are
stripped unconditionally; group/other write is stripped; resulting mode is
`0o600` for files and `0o700` for directories.

### 10.6 Delegation to the standard library

For TAR, Sentinel does not reimplement the safety logic: it passes the
`data_filter` (ARC-TARFILE) to `extractfile`/`extract` and then applies
§10.2's stricter rules on top for the paths it materialises itself. For ZIP
the standard library provides **no** equivalent guard — ARC-ZIPFILE's own
documentation names decompression bombs as a hazard and offers no limit — so
§10's counters are the only defence, which is why the ZIP branch carries the
fixture load in §11 category B.

### 10.7 Quarantine layout

```
<quarantine_root>/<root_sha256[0:2]>/<root_sha256>/<safe_rel>...    # files, mode 0o600
<quarantine_root>/.meta/<root_sha256>.json                          # per-root manifest:
    {members: [{safe_rel, original_path, sha256, size_written, size_declared,
                 rejected: null|reason, identified: <selected>, status}], limits_hit: [...]}
```

The manifest is the provenance record for every child node: it is what makes
`archive_member` canonical events reproducible, and it is what an analyst
reads when a nested artifact looks different from what the parent advertised.

---

## 11. Attack Fixture Catalogue

240 named fixtures across eight categories. Each fixture is a file (or a
script that builds one) in the Stage-4 corpus; each maps to at least one
assertion in §1, §2, §5, §6, §7, §9 or §10. Fixtures are *inputs*, never
expected outputs: the expected behaviour is stated in the assertion, so a
test can fail loudly when a parser silently "handles" a hostile input.

Naming: `FX-<category letter>-<two digits>`. Category letters:
A path/filename, B expansion, C parser-confusion, D encryption, E
active-content, F resource-exhaustion, G transport/API, H telemetry.

### Category A — path traversal and hostile filenames (30)

```yaml
fixtures_category_A:
  - {id: FX-A-01, name: zip_dotdot_plain,              desc: "ZIP member '../../etc/passwd' (POSIX traversal)"}
  - {id: FX-A-02, name: zip_dotdot_deep,               desc: "ZIP member with 64 levels of ../ prefix"}
  - {id: FX-A-03, name: zip_dotdot_embedded,           desc: "ZIP member 'docs/../../payload.exe' (mid-path traversal)"}
  - {id: FX-A-04, name: zip_backslash_traversal,       desc: "ZIP member '..\\..\\payload.exe' (Windows separator traversal)"}
  - {id: FX-A-05, name: zip_mixed_separators,          desc: "ZIP member 'a/..\\../b' mixing / and \\"}
  - {id: FX-A-06, name: zip_absolute_posix,            desc: "ZIP member '/etc/cron.d/x'"}
  - {id: FX-A-07, name: zip_absolute_drive,            desc: "ZIP member 'C:/Windows/System32/evil.dll'"}
  - {id: FX-A-08, name: zip_drive_relative,            desc: "ZIP member 'C:evil.dll' (drive-relative)"}
  - {id: FX-A-09, name: zip_unc_path,                  desc: "\\\\attacker\\share\\evil.dll as member path"}
  - {id: FX-A-10, name: zip_device_namespace_dot,      desc: "ZIP member '\\\\.\\PhysicalDrive0'"}
  - {id: FX-A-11, name: zip_device_namespace_qmark,    desc: "ZIP member '\\\\?\\C:\\evil'"}
  - {id: FX-A-12, name: zip_reserved_con,              desc: "ZIP member named 'CON'"}
  - {id: FX-A-13, name: zip_reserved_com1,             desc: "ZIP member named 'COM1.txt'"}
  - {id: FX-A-14, name: zip_reserved_lpt9_exe,         desc: "ZIP member 'LPT9.exe'"}
  - {id: FX-A-15, name: zip_reserved_superscript,      desc: "ZIP member using the superscript-COM1 reserved form"}
  - {id: FX-A-16, name: zip_ads_colon,                 desc: "ZIP member 'file.txt:Zone.Identifier' (ADS syntax)"}
  - {id: FX-A-17, name: zip_ads_colon_deep,            desc: "ZIP member 'dir/file.txt:hidden.exe'"}
  - {id: FX-A-18, name: zip_trailing_dot,              desc: "ZIP member 'payload.exe.' (Win32 silently strips)"}
  - {id: FX-A-19, name: zip_trailing_space,            desc: "ZIP member 'payload.exe '"}
  - {id: FX-A-20, name: zip_double_extension,          desc: "ZIP member 'invoice.pdf.exe'"}
  - {id: FX-A-21, name: zip_extremely_long_name,       desc: "ZIP member with a 4,000-byte filename"}
  - {id: FX-A-22, name: zip_long_component,            desc: "ZIP member with one 300-byte component"}
  - {id: FX-A-23, name: zip_deep_nesting,              desc: "ZIP with 64 nested directory components"}
  - {id: FX-A-24, name: zip_rtl_override,              desc: "ZIP member with U+202E right-to-left override spoofing the extension"}
  - {id: FX-A-25, name: zip_null_byte_name,            desc: "ZIP member whose raw name contains an embedded NUL"}
  - {id: FX-A-26, name: zip_unicode_dotdot,            desc: "ZIP member using U+2024/U+FF0E variants of '.' in '..'"}
  - {id: FX-A-27, name: tar_symlink_escape,            desc: "TAR symlink 'link -> /etc' followed by member 'link/passwd'"}
  - {id: FX-A-28, name: tar_hardlink_escape,           desc: "TAR hardlink to an absolute target outside the destination"}
  - {id: FX-A-29, name: tar_device_fifo,               desc: "TAR member declaring a FIFO/character-device entry"}
  - {id: FX-A-30, name: zip_case_collision,            desc: "ZIP with 'a.txt' and 'A.txt' on a case-insensitive target"}
```

### Category B — decompression bombs and expansion (30)

```yaml
fixtures_category_B:
  - {id: FX-B-01, name: zip_42_bomb,                   desc: "42.zip-style nested ZIP chain, ~4.5 PB declared"}
  - {id: FX-B-02, name: zip_single_huge,               desc: "single ZIP member declaring 10 GiB uncompressed of zeros"}
  - {id: FX-B-03, name: zip_high_ratio_1k,             desc: "1 KiB compressed member declaring 10 MiB output"}
  - {id: FX-B-04, name: zip_ratio_lying_size,          desc: "member declaring small size but streaming far more"}
  - {id: FX-B-05, name: zip_size_field_truncated,      desc: "ZIP64 extra field with a truncated/unreal size"}
  - {id: FX-B-06, name: zip_bzip2_bomb,                desc: "bzip2 member with extreme ratio"}
  - {id: FX-B-07, name: zip_lzma_bomb,                 desc: "LZMA member with extreme ratio"}
  - {id: FX-B-08, name: zip_deflate_stored_mismatch,   desc: "method=stored but size fields disagree"}
  - {id: FX-B-09, name: zip_central_vs_local_mismatch, desc: "central directory sizes differ from local header sizes"}
  - {id: FX-B-10, name: ooxml_10k_parts,               desc: "OOXML with 10,000 tiny parts (part-table blowup)"}
  - {id: FX-B-11, name: tar_gzip_bomb,                 desc: "tar.gz with extreme ratio across members"}
  - {id: FX-B-12, name: sevenz_bomb,                   desc: "7z with solid-block extreme ratio"}
  - {id: FX-B-13, name: gzip_header_only_oversize,     desc: "gzip member whose ISIZE trailer claims 4 GiB"}
  - {id: FX-B-14, name: zip_overlapping_members,       desc: "two members sharing the same compressed byte range"}
  - {id: FX-B-15, name: zip_million_empty,             desc: "ZIP with 1,000,000 zero-byte members"}
  - {id: FX-B-16, name: pdf_stream_bomb,               desc: "PDF stream with extreme FlateDecode ratio"}
  - {id: FX-B-17, name: pdf_jbig2_bomb,                desc: "PDF with a JBIG2 segment pattern known to expand"}
  - {id: FX-B-18, name: image_png_dimension_lie,       desc: "PNG IHDR claiming 65535x65535 with a small IDAT"}
  - {id: FX-B-19, name: image_gif_frames_bomb,         desc: "GIF with 10,000 frames"}
  - {id: FX-B-20, name: image_bmp_rle_bomb,            desc: "BMP with an RLE decompression bomb"}
  - {id: FX-B-21, name: image_tiff_tile_bomb,          desc: "TIFF with an exploding tile structure"}
  - {id: FX-B-22, name: image_webp_vp8_bomb,           desc: "WebP with extreme canvas-to-data ratio"}
  - {id: FX-B-23, name: ole_stream_oversize_declared,  desc: "OLE stream declaring a size far past EOF"}
  - {id: FX-B-24, name: cab_lzx_bomb,                  desc: "CAB with an LZX stream of extreme ratio"}
  - {id: FX-B-25, name: rar_solid_bomb,                desc: "RAR solid archive with extreme cumulative ratio"}
  - {id: FX-B-26, name: nested_zip_depth_50,           desc: "50 nested ZIPs, each 1 KiB, to hit max_depth"}
  - {id: FX-B-27, name: nested_zip_depth_8_boundary,   desc: "exactly 8 nested ZIPs (boundary of the depth limit)"}
  - {id: FX-B-28, name: fanout_20k_nodes,              desc: "one archive expanding to 20,000 nodes"}
  - {id: FX-B-29, name: zstd_bomb,                     desc: "zstd stream with extreme ratio"}
  - {id: FX-B-30, name: recursive_self_reference,      desc: "archive whose member hashes to the archive itself"}
```

### Category C — parser confusion, polyglots and format mismatch (30)

```yaml
fixtures_category_C:
  - {id: FX-C-01, name: extension_exe_as_pdf,          desc: "PE file named invoice.pdf"}
  - {id: FX-C-02, name: extension_pdf_as_exe,          desc: "PDF named setup.exe"}
  - {id: FX-C-03, name: polyglot_pdf_zip,              desc: "valid PDF whose xref is also a ZIP central directory"}
  - {id: FX-C-04, name: polyglot_pdf_js,               desc: "PDF with an embedded /JavaScript action and a JS polyglot header"}
  - {id: FX-C-05, name: polyglot_gif_exe,              desc: "GIF89a-prefixed PE (classic header splice)"}
  - {id: FX-C-06, name: polyglot_jpeg_zip,             desc: "JPEG with a complete ZIP appended after EOI"}
  - {id: FX-C-07, name: polyglot_png_pe,               desc: "PNG whose IDAT payload is a PE"}
  - {id: FX-C-08, name: polyglot_html_zip,             desc: "HTML file that is also a valid ZIP"}
  - {id: FX-C-09, name: ole_wrapping_ooxml,            desc: "OLE2 container wrapping an OOXML package"}
  - {id: FX-C-10, name: ooxml_wrapping_ole,            desc: "OOXML with an embedded OLE object containing a PE"}
  - {id: FX-C-11, name: ooxml_content_types_lie,       desc: "[Content_Types].xml declaring a type that contradicts the part bytes"}
  - {id: FX-C-12, name: zip_masquerading_ooxml,        desc: "plain ZIP with a forged [Content_Types].xml"}
  - {id: FX-C-13, name: pe_overlay_pdf,                desc: "PE with a complete PDF in its overlay"}
  - {id: FX-C-14, name: pe_fake_dos_stub,              desc: "PE whose DOS stub contains another MZ header"}
  - {id: FX-C-15, name: pe_import_table_truncated,     desc: "PE whose import table points past EOF"}
  - {id: FX-C-16, name: dotnet_in_non_pe,              desc: "CLR metadata directory declared in a non-PE"}
  - {id: FX-C-17, name: lnk_targeting_unc,             desc: "LNK whose target is an UNC path with an icon location elsewhere"}
  - {id: FX-C-18, name: lnk_with_tracker_bmp,          desc: "LNK with a Darwin/Tracker data block carrying a CLSID"}
  - {id: FX-C-19, name: rtf_with_ole_and_hex,          desc: "RTF with a hex-encoded object and an embedded OLE"}
  - {id: FX-C-20, name: rtf_objdata_cycle,             desc: "RTF \\objdata referring to itself (object graph cycle)"}
  - {id: FX-C-21, name: chm_with_pe,                   desc: "CHM whose content list includes a PE"}
  - {id: FX-C-22, name: mhtml_with_active_part,        desc: "MHTML with a part named .html and Content-Type text/html"}
  - {id: FX-C-23, name: xml_billion_laughs,             desc: "XML with recursive entity expansion (defusedxml must reject)"}
  - {id: FX-C-24, name: xml_external_entity,           desc: "XML with an external entity pointing at a file path"}
  - {id: FX-C-25, name: xml_quadratic_blowup,          desc: "XML with a single huge entity referenced many times"}
  - {id: FX-C-26, name: json_deep_nesting_10k,         desc: "JSON nested 10,000 levels (orjson/ijson recursion hazard)"}
  - {id: FX-C-27, name: csv_multiline_field,            desc: "CSV with a quoted field containing newlines and delimiters"}
  - {id: FX-C-28, name: csv_excel_formula,             desc: "CSV cell beginning =cmd|' /C calc'!A0 (injection into a spreadsheet)"}
  - {id: FX-C-29, name: zip_utf8_flag_lie,             desc: "ZIP member name claiming UTF-8 but containing invalid sequences"}
  - {id: FX-C-30, name: evtx_trailing_garbage,         desc: "EVTX with valid records followed by 1 MiB of garbage"}
```

### Category D — encryption and password handling (30)

```yaml
fixtures_category_D:
  - {id: FX-D-01, name: ooxml_encrypted_agile,         desc: "OOXML agile-encryption document, no password"}
  - {id: FX-D-02, name: ooxml_encrypted_standard,      desc: "OOXML standard (RC4) encryption"}
  - {id: FX-D-03, name: ooxml_encrypted_wrong_pw,      desc: "OOXML encrypted, attempted with the wrong password"}
  - {id: FX-D-04, name: ooxml_encrypted_known_pw,      desc: "OOXML encrypted with a workspace-configured password"}
  - {id: FX-D-05, name: ole_encrypted_doc,             desc: "legacy .doc with XOR/RC4 obfuscation"}
  - {id: FX-D-06, name: ole_encrypted_xls,             desc: "legacy .xls with CryptoAPI encryption"}
  - {id: FX-D-07, name: pdf_encrypted_v2_rc4,          desc: "PDF standard security handler V=2 R=3"}
  - {id: FX-D-08, name: pdf_encrypted_aes128,          desc: "PDF with AES-128 (V=4/R=4)"}
  - {id: FX-D-09, name: pdf_encrypted_aes256,          desc: "PDF with AES-256 (R=6)"}
  - {id: FX-D-10, name: pdf_encrypt_empty_pw,          desc: "PDF with /Encrypt and an empty user password (opens without prompting)"}
  - {id: FX-D-11, name: pdf_encrypt_owner_only,        desc: "PDF where the user password is empty but permissions are restricted"}
  - {id: FX-D-12, name: zip_crypto_entry,              desc: "ZIP with general-purpose bit 0 set on one entry"}
  - {id: FX-D-13, name: zip_aes_entry,                 desc: "ZIP with the AE-x AES extra field"}
  - {id: FX-D-14, name: zip_mixed_encrypted_plain,     desc: "ZIP with one encrypted and one plaintext member"}
  - {id: FX-D-15, name: sevenz_header_encrypted,       desc: "7z with an encrypted header"}
  - {id: FX-D-16, name: rar_encrypted_headers,         desc: "RAR with encrypted headers (listing must still work)"}
  - {id: FX-D-17, name: rar_encrypted_data,            desc: "RAR with plaintext headers and encrypted data"}
  - {id: FX-D-18, name: encrypted_nested_in_plaintext, desc: "plaintext ZIP containing an encrypted OOXML"}
  - {id: FX-D-19, name: plaintext_nested_in_encrypted, desc: "encrypted ZIP whose plaintext is a PE (decrypt-then-triage path)"}
  - {id: FX-D-20, name: pw_attempts_budget_4,          desc: "encrypted artifact needing 4 password attempts (budget is 3)"}
  - {id: FX-D-21, name: pw_slow_kdf,                   desc: "PDF with a deliberately slow KDF to hit the 5 s per-attempt budget"}
  - {id: FX-D-22, name: pw_wrong_then_right,           desc: "artifact where the 2nd configured password is correct"}
  - {id: FX-D-23, name: pw_unicode_passphrase,         desc: "password containing non-ASCII and combining characters"}
  - {id: FX-D-24, name: pw_leak_attempt,               desc: "artifact whose filename contains the password (must not be echoed into facts)"}
  - {id: FX-D-25, name: encrypted_zero_byte_plaintext, desc: "encryption wrapper around a zero-byte payload"}
  - {id: FX-D-26, name: encrypted_then_bomb,           desc: "decrypted plaintext is itself a decompression bomb"}
  - {id: FX-D-27, name: encrypted_polyglot,            desc: "encrypted OOXML that is also a valid PDF once decrypted"}
  - {id: FX-D-28, name: ooxml_encryptioninfo_truncated,desc: "EncryptionInfo part cut short"}
  - {id: FX-D-29, name: pdf_encrypt_dict_malformed,    desc: "/Encrypt referencing a missing object"}
  - {id: FX-D-30, name: efs_stream_placeholder,        desc: "file whose bytes are an EFS/BitLocker marker (must be not_analyzed_by_policy)"}
```

### Category E — active content (30)

```yaml
fixtures_category_E:
  - {id: FX-E-01, name: docm_autopen,                  desc: "DOCM with an Auto_Open VBA entry point"}
  - {id: FX-E-02, name: xlsm_workbook_open,            desc: "XLSM with Workbook_Open"}
  - {id: FX-E-03, name: pptm_auto_open,                desc: "PPTM with an auto-open macro"}
  - {id: FX-E-04, name: docx_ddefield,                 desc: "DOCX containing a DDEFIELD instruction"}
  - {id: FX-E-05, name: xlsx_xlm_sheet,                desc: "XLSX with an Excel 4.0 macro sheet and EXEC/URL calls"}
  - {id: FX-E-06, name: xlsb_binary_macro,             desc: "XLSB with a binary macro payload"}
  - {id: FX-E-07, name: ooxml_external_template,       desc: "DOCX relationship with TargetMode=External pointing at a .dotx"}
  - {id: FX-E-08, name: ooxml_external_ole,            desc: "OLE relationship to an external moniker"}
  - {id: FX-E-09, name: oooxml_html_fallback,          desc: "Word HTML fallback part with an external image"}
  - {id: FX-E-10, name: doc_vba_stomped,               desc: "OLE .doc with a stomped (empty) _VBA_PROJECT but a live module stream"}
  - {id: FX-E-11, name: ole_oleobject_package,         desc: "OLE Package object whose payload is a PE"}
  - {id: FX-E-12, name: pdf_openaction_js,             desc: "PDF /OpenAction /JavaScript"}
  - {id: FX-E-13, name: pdf_openaction_launch,         desc: "PDF /OpenAction /Launch"}
  - {id: FX-E-14, name: pdf_additional_actions,        desc: "PDF /AA /WC and /WS page actions"}
  - {id: FX-E-15, name: pdf_submit_form,               desc: "PDF /SubmitForm to an http URL"}
  - {id: FX-E-16, name: pdf_import_data,               desc: "PDF /ImportData referencing an external file"}
  - {id: FX-E-17, name: pdf_xfa_form,                  desc: "PDF with an XFA form packet"}
  - {id: FX-E-18, name: pdf_richmedia_annotation,      desc: "PDF with a /RichMedia annotation"}
  - {id: FX-E-19, name: rtf_with_objauto,              desc: "RTF using \\objauto and an embedded OLE object"}
  - {id: FX-E-20, name: rtf_includePicture_url,        desc: "RTF \\includepicture pointing at an http URL"}
  - {id: FX-E-21, name: ps1_base64_encodedcommand,     desc: "PowerShell script with -EncodedCommand style base64 blob"}
  - {id: FX-E-22, name: ps1_invoke_expression,         desc: "PowerShell script calling Invoke-Expression on a concatenated string"}
  - {id: FX-E-23, name: ps1_downloadstring,            desc: "PowerShell script with DownloadString"}
  - {id: FX-E-24, name: js_wscript_shell,              desc: "JScript using WScript.Shell and ActiveXObject"}
  - {id: FX-E-25, name: vbs_createobject,              desc: "VBScript creating Shell.Application"}
  - {id: FX-E-26, name: hta_inline_script,             desc: "HTA with an inline script block"}
  - {id: FX-E-27, name: html_meta_refresh,             desc: "HTML with <meta http-equiv=refresh content=0;url=...>"}
  - {id: FX-E-28, name: html_external_script,          desc: "HTML referencing an external script URI"}
  - {id: FX-E-29, name: lnk_powershell_arguments,      desc: "LNK whose target is powershell.exe with an encoded argument"}
  - {id: FX-E-30, name: chm_with_active_html,          desc: "CHM whose default topic contains script (metadata-only path must hold)"}
```

### Category F — resource exhaustion and fan-out (30)

```yaml
fixtures_category_F:
  - {id: FX-F-01, name: evtx_1m_records,               desc: "EVTX with 1,000,000 small records (event-count cap)"}
  - {id: FX-F-02, name: evtx_single_huge_record,       desc: "one EVTX record carrying 50 MiB of event data"}
  - {id: FX-F-03, name: evtx_deeply_nested_xml,        desc: "EVTX whose rendered XML nests 10,000 elements"}
  - {id: FX-F-04, name: pcap_10k_flows,                desc: "pcap with 10,000 distinct flows"}
  - {id: FX-F-05, name: pcap_single_huge_packet,       desc: "pcap with a snaplen-truncated 16 MiB packet"}
  - {id: FX-F-06, name: pcap_infinite_tcp_stream,      desc: "pcap with one stream of 1,000,000 segments"}
  - {id: FX-F-07, name: pcap_malformed_dissector,      desc: "pcap crafted to hit a known dissector crash class"}
  - {id: FX-F-08, name: eve_1m_lines,                  desc: "Suricata eve.json with 1,000,000 lines"}
  - {id: FX-F-09, name: eve_line_10mb,                 desc: "one eve.json line of 10 MiB"}
  - {id: FX-F-10, name: zeek_1m_rows,                  desc: "Zeek conn.log with 1,000,000 rows"}
  - {id: FX-F-11, name: ooxml_8k_relationships,        desc: "one .rels part with 8,000 relationship entries"}
  - {id: FX-F-12, name: pdf_10k_objects,               desc: "PDF with 10,000 indirect objects"}
  - {id: FX-F-13, name: pdf_circular_refs,             desc: "PDF with a reference cycle between indirect objects"}
  - {id: FX-F-14, name: ole_1k_streams,                desc: "OLE container with 1,000 streams"}
  - {id: FX-F-15, name: pe_1k_sections,                desc: "PE declaring 1,000 sections"}
  - {id: FX-F-16, name: pe_100k_imports,               desc: "PE importing 100,000 symbols"}
  - {id: FX-F-17, name: dotnet_huge_us_string_heap,    desc: ".NET metadata with a 50 MiB #US heap"}
  - {id: FX-F-18, name: rtf_1m_groups,                 desc: "RTF with 1,000,000 nested groups"}
  - {id: FX-F-19, name: rtf_hex_run_50mb,              desc: "RTF with a single 50 MiB hex-encoded run"}
  - {id: FX-F-20, name: script_10mb_line,              desc: "PowerShell script with one 10 MiB line"}
  - {id: FX-F-21, name: csv_1m_rows,                   desc: "CSV with 1,000,000 rows"}
  - {id: FX-F-22, name: csv_10k_columns,               desc: "CSV with 10,000 columns"}
  - {id: FX-F-23, name: nmap_10k_hosts,                desc: "Nmap XML with 10,000 hosts"}
  - {id: FX-F-24, name: xml_1m_elements,               desc: "XML with 1,000,000 elements (defusedxml + memory)"}
  - {id: FX-F-25, name: yaml_billion_laughs,           desc: "YAML with recursive anchor expansion (if YAML is accepted)"}
  - {id: FX-F-26, name: json_1m_keys,                  desc: "JSON object with 1,000,000 keys"}
  - {id: FX-F-27, name: zip_65535_entries_32bit,       desc: "ZIP at the 16-bit entry-count boundary without ZIP64"}
  - {id: FX-F-28, name: zip64_entry_count_huge,        desc: "ZIP64 declaring an enormous entry count"}
  - {id: FX-F-29, name: multipart_1000_parts,          desc: "multipart upload with 1,000 non-file parts"}
  - {id: FX-F-30, name: graph_shared_subtree_1k,       desc: "one archive embedding the same child 1,000 times (dedup path)"}
```

### Category G — transport and API abuse (30)

```yaml
fixtures_category_G:
  - {id: FX-G-01, name: upload_zero_bytes,             desc: "empty file part (GATE_EMPTY_FILE)"}
  - {id: FX-G-02, name: upload_over_max_size,          desc: "file part one byte over max_file_bytes"}
  - {id: FX-G-03, name: upload_declared_lie_small,     desc: "Content-Length smaller than the body actually sent"}
  - {id: FX-G-04, name: upload_declared_lie_large,     desc: "Content-Length larger than the body actually sent"}
  - {id: FX-G-05, name: upload_chunked_no_length,      desc: "chunked transfer with no Content-Length (must be accepted)"}
  - {id: FX-G-06, name: upload_slow_body,              desc: "body trickled at 1 byte/s to hit the wall-clock bound"}
  - {id: FX-G-07, name: upload_filename_nul,           desc: "multipart filename containing %00"}
  - {id: FX-G-08, name: upload_filename_traversal,     desc: "multipart filename ../../etc/passwd"}
  - {id: FX-G-09, name: upload_filename_reserved,      desc: "multipart filename CON"}
  - {id: FX-G-10, name: upload_filename_rtl,           desc: "multipart filename with U+202E override"}
  - {id: FX-G-11, name: upload_filename_huge,          desc: "multipart filename of 64 KiB"}
  - {id: FX-G-12, name: upload_filename_invalid_utf8,  desc: "multipart filename with invalid UTF-8 bytes"}
  - {id: FX-G-13, name: upload_two_files,              desc: "two file parts (GATE_TOO_MANY_FILES)"}
  - {id: FX-G-14, name: upload_field_huge,             desc: "non-file part of 1 MiB (GATE_FIELD_TOO_LARGE)"}
  - {id: FX-G-15, name: upload_tenant_mismatch,        desc: "authenticated principal uploading into another tenant"}
  - {id: FX-G-16, name: upload_unauthenticated,        desc: "request with no credentials"}
  - {id: FX-G-17, name: upload_idempotency_mismatch,   desc: "Idempotency-Key reuse with different content"}
  - {id: FX-G-18, name: upload_idempotent_replay,      desc: "identical Idempotency-Key and content (must dedupe)"}
  - {id: FX-G-19, name: upload_rate_burst,             desc: "100 concurrent uploads from one principal"}
  - {id: FX-G-20, name: upload_huge_valid,             desc: "a valid 60 MiB artifact just under the cap (timing)"}
  - {id: FX-G-21, name: upload_content_type_lie,       desc: "Content-Type: application/pdf with PE bytes"}
  - {id: FX-G-22, name: upload_boundary_attack,        desc: "multipart body crafted to confuse the boundary parser"}
  - {id: FX-G-23, name: upload_nested_multipart,       desc: "multipart inside a multipart part"}
  - {id: FX-G-24, name: upload_crlf_in_header,         desc: "header value containing CR/LF (response-splitting attempt)"}
  - {id: FX-G-25, name: upload_duplicate_hash_different_name, desc: "same bytes, different filenames (dedup + display collision)"}
  - {id: FX-G-26, name: upload_quota_exhaust,          desc: "upload that would exceed the tenant quota"}
  - {id: FX-G-27, name: upload_unicode_normalisation,  desc: "filename differing only by NFC/NFD normalization"}
  - {id: FX-G-28, name: upload_reserved_header,        desc: "Hop-by-hop and trailer header abuse"}
  - {id: FX-G-29, name: upload_expect_100_stall,       desc: "Expect: 100-continue stall"}
  - {id: FX-G-30, name: upload_disposition_filename_only, desc: "no multipart filename, only Content-Disposition in a sub-part"}
```

### Category H — telemetry parser adversarial inputs (30)

```yaml
fixtures_category_H:
  - {id: FX-H-01, name: evtx_large_clean,              desc: "1 GiB well-formed EVTX (throughput baseline)"}
  - {id: FX-H-02, name: evtx_truncated_mid_record,     desc: "EVTX cut in the middle of a record"}
  - {id: FX-H-03, name: evtx_bad_checksum,             desc: "EVTX record with a corrupted checksum"}
  - {id: FX-H-04, name: evtx_invalid_utf16,            desc: "EVTX event data with unpaired surrogates"}
  - {id: FX-H-05, name: pcap_medium_clean,             desc: "100 MiB well-formed pcap (TShark timing baseline)"}
  - {id: FX-H-06, name: pcap_memory_stress,            desc: "pcap crafted to maximise dissector memory"}
  - {id: FX-H-07, name: pcap_truncated_header,         desc: "pcap with a file header only"}
  - {id: FX-H-08, name: tenk_records_mixed,            desc: "10,000 records across channels (latency baseline)"}
  - {id: FX-H-09, name: worker_memory_stress,          desc: "harvest sized to hit the per-worker memory ceiling"}
  - {id: FX-H-10, name: schema_violating_event,        desc: "synthetic source record engineered to break a mapping (must be source_contract)"}
  - {id: FX-H-11, name: zeek_missing_fields_header,    desc: "Zeek log with no #fields line"}
  - {id: FX-H-12, name: zeek_column_count_mismatch,    desc: "Zeek row with more columns than #fields declares"}
  - {id: FX-H-13, name: zeek_missing_column,           desc: "Zeek row with fewer columns than declared"}
  - {id: FX-H-14, name: zeek_ts_not_numeric,           desc: "Zeek ts field that is not an epoch float"}
  - {id: FX-H-15, name: eve_invalid_json_line,         desc: "eve.json line 500 is truncated JSON"}
  - {id: FX-H-16, name: eve_event_type_unknown,        desc: "eve.json with an unrecognised event_type"}
  - {id: FX-H-17, name: eve_json_bomb_line,            desc: "one eve line nested 5,000 levels"}
  - {id: FX-H-18, name: syslog_rfc5424_bom,            desc: "5424 line with a UTF-8 BOM and non-UTF-8 payload"}
  - {id: FX-H-19, name: syslog_3164_truncated_pri,     desc: "3164 line with a malformed PRI"}
  - {id: FX-H-20, name: syslog_missing_newline,        desc: "syslog stream with no trailing newline"}
  - {id: FX-H-21, name: cef_escaped_pipe,              desc: "CEF extension value containing an escaped pipe"}
  - {id: FX-H-22, name: cef_unterminated_header,       desc: "CEF header cut before the final pipe"}
  - {id: FX-H-23, name: leef_custom_delimiter,         desc: "LEEF 2.0 with a custom delimiter character"}
  - {id: FX-H-24, name: leef_missing_header,           desc: "LEEF attribute block with no LEEF header"}
  - {id: FX-H-25, name: csv_injection_export,          desc: "CSV whose first cell begins with ="}
  - {id: FX-H-26, name: reg_export_utf16_bom,          desc: "reg export file with a UTF-16 BOM"}
  - {id: FX-H-27, name: netstat_locale_comma,          desc: "netstat output produced under a locale using comma decimals"}
  - {id: FX-H-28, name: nmap_xml_doctype_external,     desc: "Nmap XML with an external DOCTYPE (must be rejected)"}
  - {id: FX-H-29, name: nmap_xml_namespace_prefix,     desc: "Nmap XML with unexpected namespace prefixes"}
  - {id: FX-H-30, name: encoding_mixed_utf8_latin1,    desc: "text log mixing UTF-8 and Latin-1 in one file"}
```

**Coverage mapping.** Every normative limit in §1, §2, §5, §6, §7 and §10
names a fixture above; the four §4 telemetry budgets name FX-H-01, FX-H-05,
FX-H-08 and FX-H-09. A Stage-4 benchmark run that does not execute all 240
fixtures has not validated this document.

---
