"""MCP tools for PE forensics — YARA rule generation, authenticode parsing, artifact timeline."""
import asyncio
import datetime
import hashlib
import io
import struct
import warnings

from typing import Dict, Any, List, Optional

from arkana.config import (
    state, logger, Context, pefile,
    CRYPTOGRAPHY_AVAILABLE, SIGNIFY_AVAILABLE, YARA_AVAILABLE,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_pe_object, _check_mcp_response_size
from arkana.mcp._refinery_helpers import _write_output_and_register_artifact

if CRYPTOGRAPHY_AVAILABLE:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.hazmat.primitives import hashes as crypto_hashes

if SIGNIFY_AVAILABLE:
    from signify.authenticode import AuthenticodeFile


# ===================================================================
#  Tool 1: generate_yara_rule
# ===================================================================

@tool_decorator
async def generate_yara_rule(
    ctx: Context,
    rule_name: Optional[str] = None,
    include_strings: bool = True,
    include_imports: bool = True,
    include_rich_header: bool = False,
    include_pdb: bool = True,
    max_strings: int = 15,
    min_string_length: int = 6,
    scan_after_generate: bool = False,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: utility] Auto-generates a YARA rule from the loaded binary's analysis
    findings: unique strings, import combinations, section names, Rich header hash,
    PDB path, file size range, and byte patterns. Outputs valid YARA syntax.

    ---compact: auto-generate YARA rule | strings, imports, Rich header, PDB | needs: file

    When to use: After analysis is complete and you want a detection signature
    for the sample. The generated rule is a starting point — review and refine
    before production use.

    Next steps: Test with search_yara_custom() against other samples, refine
    conditions, add_note() to record the rule.

    Args:
        ctx: MCP Context.
        rule_name: Custom rule name. Auto-generated from sample if not provided.
        include_strings: Include distinctive strings in the rule. Default True.
        include_imports: Include import-based conditions. Default True.
        include_rich_header: Include Rich header hash condition. Default False.
        include_pdb: Include PDB path if found. Default True.
        max_strings: Max string indicators to include. Default 15.
        min_string_length: Min length for string candidates. Default 6.
        scan_after_generate: If True, immediately scan the loaded binary with
            the generated rule and include match results. Requires yara-python.
        output_path: (Optional[str]) Save YARA rule to this path and register as artifact.
    """
    await ctx.info("Generating YARA rule")
    _check_pe_loaded("generate_yara_rule")

    pe_data = state.pe_data or {}
    hashes = pe_data.get("file_hashes", {})
    triage = getattr(state, '_cached_triage', None) or {}

    def _generate():
        # Determine rule name
        name = rule_name
        if not name:
            sha = hashes.get("sha256", "unknown")[:8]
            mode = pe_data.get("mode", "pe").lower()
            name = f"mal_{mode}_{sha}"
        # Sanitize: YARA identifiers are [a-zA-Z0-9_]
        name = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
        if not name:
            name = "rule_unknown"
        if name[0].isdigit():
            name = "rule_" + name

        meta_lines = []
        string_defs = []
        condition_parts = []
        string_idx = 0

        # --- Meta ---
        meta_lines.append(f'        description = "Auto-generated rule for {hashes.get("sha256", "unknown")}"')
        meta_lines.append(f'        sha256 = "{hashes.get("sha256", "")}"')
        meta_lines.append(f'        date = "{datetime.date.today().isoformat()}"')
        meta_lines.append(f'        generator = "Arkana generate_yara_rule"')

        # --- Strings: distinctive strings from triage/notes ---
        if include_strings:
            candidates = _collect_string_candidates(pe_data, triage, min_string_length)
            for s in candidates[:max_strings]:
                var_name = f"$s{string_idx}"
                # Escape YARA special chars (backslash first, then quotes, then control chars)
                escaped = s.replace("\\", "\\\\").replace('"', '\\"')
                escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                string_defs.append(f'        {var_name} = "{escaped}"')
                string_idx += 1

            if string_defs:
                count = max(len(string_defs) // 2, 1)
                string_refs = ", ".join(f"$s{i}" for i in range(len(string_defs)))
                condition_parts.append(f"{count} of ({string_refs})")

        # --- PDB path ---
        if include_pdb:
            debug_info = pe_data.get("debug_info", [])
            if isinstance(debug_info, list):
                for dbg in debug_info:
                    if isinstance(dbg, dict):
                        pdb = dbg.get("pdb_filename")
                        if pdb and len(pdb) > 4:
                            var_name = f"$pdb{string_idx}"
                            escaped = pdb.replace("\\", "\\\\").replace('"', '\\"')
                            escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                            string_defs.append(f'        {var_name} = "{escaped}"')
                            condition_parts.append(f"{var_name}")
                            string_idx += 1
                            break

        # --- Import-based conditions ---
        if include_imports:
            imports_data = pe_data.get("imports", [])
            import_conditions = _build_import_conditions(imports_data, triage)
            if import_conditions:
                condition_parts.extend(import_conditions)

        # --- Rich header hash ---
        if include_rich_header:
            rich = pe_data.get("rich_header")
            if isinstance(rich, dict) and rich.get("clear_data_hex"):
                try:
                    clear_data = bytes.fromhex(rich["clear_data_hex"])
                    rich_md5 = hashlib.md5(clear_data, usedforsecurity=False).hexdigest()  # H1-v10
                    condition_parts.append(f'hash.md5(pe.rich_signature.clear_data) == "{rich_md5}"')
                    meta_lines.append(f'        rich_hash = "{rich_md5}"')
                except Exception:
                    pass

        # --- File size condition ---
        try:
            file_size = pe_data.get("file_size")
            if not file_size:
                import os
                file_size = os.path.getsize(state.filepath)
            if isinstance(file_size, (int, float)):
                size = int(file_size)
                # Allow 20% variance
                lo = int(size * 0.8)
                hi = int(size * 1.2)
                condition_parts.append(f"filesize > {lo} and filesize < {hi}")
        except Exception:
            pass

        # --- PE header condition ---
        condition_parts.insert(0, "uint16(0) == 0x5A4D")

        # --- Build the rule ---
        imports_needed = set()
        for c in condition_parts:
            if "pe." in c or "pe.rich_signature" in c:
                imports_needed.add("pe")
            if "hash." in c:
                imports_needed.add("hash")

        import_line = ""
        if imports_needed:
            import_line = 'import "' + '"\nimport "'.join(sorted(imports_needed)) + '"\n\n'

        meta_block = "\n".join(meta_lines)
        strings_block = "\n".join(string_defs) if string_defs else ""
        condition_block = " and\n        ".join(condition_parts)

        rule = f"""{import_line}rule {name}
{{
    meta:
{meta_block}
"""
        if strings_block:
            rule += f"""
    strings:
{strings_block}
"""
        rule += f"""
    condition:
        {condition_block}
}}
"""
        return {
            "rule_name": name,
            "rule": rule,
            "string_count": len(string_defs),
            "condition_count": len(condition_parts),
            "imports_used": sorted(imports_needed),
        }

    result = await asyncio.to_thread(_generate)

    # Optionally scan the loaded binary with the generated rule
    if scan_after_generate:
        if not YARA_AVAILABLE:
            result["scan_error"] = "yara-python not installed — cannot scan"
        else:
            import yara
            rule_text = result.get("rule", "")
            try:
                # M2-v8: Disable includes even for generated rules (defense in depth)
                compiled = yara.compile(source=rule_text, includes=False)
                matches = compiled.match(state.filepath, timeout=120)  # M4-v9: match timeout
                scan_results = []
                for match in matches:
                    match_info: Dict[str, Any] = {
                        "rule": match.rule,
                        "tags": list(match.tags) if match.tags else [],
                        "meta": dict(match.meta) if match.meta else {},
                    }
                    string_matches = []
                    for s in match.strings:
                        for instance in s.instances[:20]:
                            string_matches.append({
                                "identifier": s.identifier,
                                "offset": instance.offset,
                                "matched_data": instance.matched_data.hex()[:64],
                            })
                    match_info["strings"] = string_matches[:20]
                    if len(string_matches) > 20:
                        match_info["strings_pagination"] = {"total": len(string_matches), "returned": 20, "has_more": True}
                    scan_results.append(match_info)
                result["scan_result"] = {
                    "matched": len(scan_results) > 0,
                    "match_count": len(scan_results),
                    "matches": scan_results,
                }
            except yara.SyntaxError as e:
                result["scan_error"] = f"YARA compilation error: {e}"
            except Exception as e:
                result["scan_error"] = f"YARA scan error: {e}"

    if output_path:
        rule_text = result.get("rule", "")
        text_bytes = rule_text.encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "generate_yara_rule",
            f"YARA rule: {result.get('rule_name', 'unknown')}",
        )
        result["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, result, "generate_yara_rule")


def _collect_string_candidates(
    pe_data: Dict, triage: Dict, min_length: int,
) -> List[str]:
    """Collect distinctive strings from the binary suitable for YARA rules.

    Sources (in priority order):
    1. FLOSS decoded/stack strings (strongest signal — runtime-extracted)
    2. Suspicious strings identified by triage (flagged by heuristics)
    3. Network IOCs from triage (URLs, domains, IPs found in binary)
    4. Basic ASCII strings from PE parse (fallback)
    """
    _MAX_CANDIDATES = 60
    candidates: List[str] = []
    seen: set = set()

    def _add(s: str) -> None:
        if (isinstance(s, str) and len(s) >= min_length
                and s not in seen and s.isprintable()
                and len(candidates) < _MAX_CANDIDATES):
            candidates.append(s)
            seen.add(s)

    # 1. FLOSS decoded and stack strings (highest value for detection)
    floss = pe_data.get("floss_analysis") or {}
    floss_strings = floss.get("strings", {})
    if isinstance(floss_strings, dict):
        for s_entry in floss_strings.get("decoded_strings", []):
            s = s_entry.get("string", s_entry) if isinstance(s_entry, dict) else str(s_entry)
            _add(s)
        for s_entry in floss_strings.get("stack_strings", []):
            s = s_entry.get("string", s_entry) if isinstance(s_entry, dict) else str(s_entry)
            _add(s)

    # 2. High-value strings from triage (ML-ranked by StringSifter)
    hvs = triage.get("high_value_strings", [])
    if isinstance(hvs, list):
        for item in hvs:
            s = item.get("string", item) if isinstance(item, dict) else str(item)
            _add(s)

    # 3. Network IOCs extracted from binary by triage
    net_iocs = triage.get("network_iocs", {})
    if isinstance(net_iocs, dict):
        for key in ["urls", "domains", "ip_addresses"]:
            for item in net_iocs.get(key, []):
                if isinstance(item, str):
                    _add(item)

    # 4. Fallback: basic ASCII strings from PE parse
    if len(candidates) < 5:
        basic_strings = pe_data.get("basic_ascii_strings", [])
        if isinstance(basic_strings, list):
            # Items are dicts: {"offset": "0x...", "string": "...", "source_type": "..."}
            raw = []
            for item in basic_strings:
                if isinstance(item, dict):
                    raw.append(item.get("string", ""))
                elif isinstance(item, str):
                    raw.append(item)
            # Prefer longer, more distinctive strings
            sorted_strings = sorted(
                (s for s in raw if isinstance(s, str) and len(s) >= min_length),
                key=len, reverse=True,
            )
            for s in sorted_strings:
                _add(s)

    return candidates


def _build_import_conditions(imports_data: Any, triage: Dict) -> List[str]:
    """Build YARA pe.imports() conditions from suspicious imports."""
    conditions = []
    sus_imports = triage.get("suspicious_imports", [])

    # Group by DLL
    dll_funcs: Dict[str, List[str]] = {}
    if isinstance(sus_imports, list):
        for imp in sus_imports:
            if isinstance(imp, dict):
                dll = imp.get("dll", "").lower()
                func = imp.get("function", "")
                risk = imp.get("risk", "")
                if dll and func and risk in ("CRITICAL", "HIGH"):
                    if dll not in dll_funcs:
                        dll_funcs[dll] = []
                    dll_funcs[dll].append(func)

    # Generate conditions for up to 3 DLLs, 2 functions each
    count = 0
    for dll, funcs in sorted(dll_funcs.items(), key=lambda x: -len(x[1])):
        if count >= 3:
            break
        for func in funcs[:2]:
            conditions.append(f'pe.imports("{dll}", "{func}")')
        count += 1

    return conditions


# ===================================================================
#  Tool 2: parse_authenticode
# ===================================================================

@tool_decorator
async def parse_authenticode(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: explore] Parses PE authenticode signatures: extracts certificate details
    (subject, issuer, serial, thumbprint, validity), countersignature timestamps,
    validates the PE hash against the signed hash, and detects anomalies (expired,
    self-signed, mismatched hashes). Does not perform chain-of-trust verification.

    ---compact: parse authenticode signature | certs, thumbprints, hash validation | needs: PE

    When to use: When investigating signed malware, supply chain attacks, stolen
    code signing certificates, or validating binary authenticity.

    Next steps: If signature anomalies found → add_note() to record findings.
    Compare certificate thumbprints across samples for attribution.

    Args:
        ctx: MCP Context.
    """
    await ctx.info("Parsing authenticode signature")
    _check_pe_loaded("parse_authenticode")
    _check_pe_object("parse_authenticode", require_headers=True)

    pe = state.pe_object

    def _parse():
        result: Dict[str, Any] = {}
        anomalies: List[Dict[str, Any]] = []

        # Check for security directory
        sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        if not (hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY')
                and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx):
            result["signed"] = False
            result["reason"] = "No security data directory"
            return result

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
        sig_offset = sec_dir.VirtualAddress
        sig_size = sec_dir.Size

        if sig_offset == 0 or sig_size == 0:
            result["signed"] = False
            result["reason"] = "Security directory is empty"
            return result

        result["signed"] = True
        result["signature_offset"] = hex(sig_offset)
        result["signature_size"] = sig_size

        # Extract raw signature block
        try:
            raw_sig = pe.get_data(sig_offset, sig_size)
        except Exception as e:
            result["error"] = f"Failed to read signature data: {e}"
            return result

        # Parse WIN_CERTIFICATE structure
        if len(raw_sig) >= 8:
            cert_length = struct.unpack_from('<I', raw_sig, 0)[0]
            cert_revision = struct.unpack_from('<H', raw_sig, 4)[0]
            cert_type = struct.unpack_from('<H', raw_sig, 6)[0]
            result["certificate_table"] = {
                "length": cert_length,
                "revision": hex(cert_revision),
                "type": "PKCS7" if cert_type == 0x0002 else f"Unknown (0x{cert_type:04x})",
            }

        # Parse certificates with cryptography library
        if CRYPTOGRAPHY_AVAILABLE:
            certs = _parse_certificates_crypto(raw_sig, anomalies)
            result["certificates"] = certs
        else:
            result["certificates"] = []
            result["certificate_note"] = "cryptography library not available — install for certificate details"

        # Validate with signify
        if SIGNIFY_AVAILABLE:
            validation = _validate_with_signify(pe, anomalies)
            result["validation"] = validation
        else:
            result["validation"] = {"note": "signify library not available — install for signature validation"}

        # PE hash validation (compute Authenticode PE hash)
        pe_hash = _compute_authenticode_hash(pe)
        if pe_hash:
            result["authenticode_sha256"] = pe_hash

        result["anomalies"] = anomalies
        return result

    analysis = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, analysis, "parse_authenticode")


def _parse_certificates_crypto(raw_sig: bytes, anomalies: List) -> List[Dict[str, Any]]:
    """Parse certificates from raw signature using cryptography library."""
    certs_info = []
    try:
        pkcs7_blob = None
        if len(raw_sig) > 8:
            cert_type = struct.unpack_from('<H', raw_sig, 6)[0]
            if cert_type == 0x0002:
                pkcs7_blob = raw_sig[8:]

        if not pkcs7_blob:
            return certs_info

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            parsed_certs = pkcs7.load_der_pkcs7_certificates(pkcs7_blob)

        now = datetime.datetime.now(datetime.timezone.utc)

        for idx, cert in enumerate(parsed_certs):
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()

            # Compute thumbprint
            try:
                thumbprint = cert.fingerprint(crypto_hashes.SHA256()).hex()
            except Exception:
                thumbprint = None

            cert_info = {
                "index": idx,
                "subject": subject,
                "issuer": issuer,
                "serial_number": str(cert.serial_number),
                "thumbprint_sha256": thumbprint,
                "not_before": str(cert.not_valid_before_utc),
                "not_after": str(cert.not_valid_after_utc),
                "version": str(cert.version),
            }

            # Check for self-signed
            if subject == issuer:
                cert_info["self_signed"] = True
                anomalies.append({
                    "type": "self_signed",
                    "severity": "medium",
                    "description": f"Certificate {idx} is self-signed: {subject}",
                })

            # Check expiry
            try:
                not_after = cert.not_valid_after_utc
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=datetime.timezone.utc)
                if not_after < now:
                    cert_info["expired"] = True
                    anomalies.append({
                        "type": "expired_cert",
                        "severity": "low",
                        "description": f"Certificate {idx} expired on {not_after}",
                    })
            except Exception:
                pass

            # Check for very short validity period (suspicious)
            try:
                validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
                cert_info["validity_days"] = validity_days
                if validity_days < 30:
                    anomalies.append({
                        "type": "short_validity",
                        "severity": "medium",
                        "description": f"Certificate {idx} has very short validity: {validity_days} days",
                    })
            except Exception:
                pass

            certs_info.append(cert_info)

    except Exception as e:
        logger.debug("Certificate parsing error: %s", e)
        certs_info.append({"error": str(e)[:200]})

    return certs_info


def _validate_with_signify(pe: "pefile.PE", anomalies: List) -> Dict[str, Any]:
    """Validate authenticode signature using signify."""
    try:
        # Use in-memory PE data to avoid TOCTOU and extra disk read
        auth_file = AuthenticodeFile.from_stream(io.BytesIO(pe.__data__))
        status, err = auth_file.explain_verify()

        result = {
            "status": str(status),
            "valid": "OK" in str(status),
            "error": str(err) if err else None,
        }

        # Extract signer info
        signers = []
        countersigs = []
        for sig in auth_file.signatures:
            if hasattr(sig, 'signer_info') and sig.signer_info:
                si = sig.signer_info
                signer = {}
                if hasattr(si, 'program_name') and si.program_name:
                    signer["program_name"] = si.program_name
                if hasattr(si, 'issuer'):
                    signer["issuer"] = str(si.issuer)
                signers.append(signer)

                # Countersignatures (timestamps)
                if hasattr(si, 'countersigner') and si.countersigner:
                    cs = si.countersigner
                    cs_info = {}
                    if hasattr(cs, 'signing_time'):
                        cs_info["timestamp"] = str(cs.signing_time)
                    countersigs.append(cs_info)

        result["signers"] = signers
        result["countersignatures"] = countersigs

        if not result["valid"]:
            anomalies.append({
                "type": "invalid_signature",
                "severity": "high",
                "description": f"Signature validation failed: {status}",
            })

        return result

    except Exception as e:
        return {"error": f"Signify validation failed: {e}"}


def _compute_authenticode_hash(pe: "pefile.PE") -> Optional[str]:
    """Compute the Authenticode PE image hash (SHA-256).

    This excludes the checksum field, the security directory entry,
    and the signature data itself — matching what the signer hashes.
    """
    try:
        data = pe.__data__
        h = hashlib.sha256()

        # PE checksum offset: e_lfanew + 24 + 64 = offset to CheckSum in optional header
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 24 + 68 > len(data):
            logger.debug("Authenticode hash: e_lfanew (0x%x) points beyond data", pe_offset)
            return None
        checksum_offset = pe_offset + 24 + 64

        # Security directory entry offset: after checksum, in data directories
        # For PE32: optional header offset + 128 (4th directory, each is 8 bytes)
        # For PE32+: optional header offset + 144
        optional_header_offset = pe_offset + 24
        magic = struct.unpack_from('<H', data, optional_header_offset)[0]
        if magic == 0x20B:  # PE32+
            sec_dir_offset = optional_header_offset + 144
        elif magic == 0x10B:  # PE32
            sec_dir_offset = optional_header_offset + 128
        else:
            logger.debug("Authenticode hash: unknown PE magic 0x%x", magic)
            return None

        if sec_dir_offset + 8 > len(data):
            return None

        # Get signature location
        sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
        sig_offset = sec_dir.VirtualAddress

        # Hash everything except:
        # 1. Checksum field (4 bytes at checksum_offset)
        # 2. Security directory entry (8 bytes at sec_dir_offset)
        # 3. Signature data (from sig_offset to end, if present)

        h.update(data[:checksum_offset])
        h.update(data[checksum_offset + 4:sec_dir_offset])
        h.update(data[sec_dir_offset + 8:sig_offset if sig_offset else len(data)])

        return h.hexdigest()
    except Exception as e:
        logger.debug("Authenticode hash computation failed: %s", e)
        return None


# ===================================================================
#  Tool 3: unify_artifact_timeline
# ===================================================================

@tool_decorator
async def unify_artifact_timeline(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: utility] Correlates all temporal artifacts from the binary:
    PE compile timestamp, debug directory timestamps, Rich header build info,
    resource timestamps, export table timestamp, digital signature timestamps,
    and .NET metadata version. Flags anomalies like timestomping, future dates,
    and mismatches between components.

    ---compact: unify temporal artifacts into timeline | timestomping detection | needs: PE

    When to use: When investigating binary provenance, build timeline, or
    suspected timestamp tampering/timestomping.

    Next steps: If anomalies found → add_note() to record findings. Use
    compute_similarity_hashes() and analyze_debug_directory() for deeper
    provenance analysis.

    Args:
        ctx: MCP Context.
    """
    await ctx.info("Building artifact timeline")
    _check_pe_loaded("unify_artifact_timeline")
    _check_pe_object("unify_artifact_timeline", require_headers=True)

    pe = state.pe_object
    pe_data = state.pe_data or {}

    def _analyze():
        artifacts: List[Dict[str, Any]] = []
        anomalies: List[Dict[str, Any]] = []
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        # --- 1. PE compile timestamp ---
        pe_ts = pe.FILE_HEADER.TimeDateStamp
        artifacts.append({
            "source": "PE header (TimeDateStamp)",
            "timestamp": pe_ts,
            "human": _ts_str(pe_ts),
            "type": "compile_time",
        })

        # --- 2. Debug directory timestamps ---
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for i, entry in enumerate(pe.DIRECTORY_ENTRY_DEBUG):
                dbg_ts = entry.struct.TimeDateStamp
                dbg_type = entry.struct.Type
                type_name = {2: "CodeView", 13: "POGO", 14: "ILTCG"}.get(dbg_type, f"Type_{dbg_type}")
                artifacts.append({
                    "source": f"Debug directory [{i}] ({type_name})",
                    "timestamp": dbg_ts,
                    "human": _ts_str(dbg_ts),
                    "type": "debug_time",
                })

                # PDB path as metadata (not a timestamp, but relevant to provenance)
                if entry.entry and hasattr(entry.entry, 'PdbFileName'):
                    try:
                        pdb = entry.entry.PdbFileName.decode('utf-8', 'ignore').rstrip('\x00')
                        artifacts.append({
                            "source": "PDB path",
                            "value": pdb,
                            "type": "metadata",
                        })
                    except Exception:
                        pass

        # --- 3. Export table timestamp ---
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exp = pe.DIRECTORY_ENTRY_EXPORT
            if hasattr(exp, 'struct'):
                exp_ts = exp.struct.TimeDateStamp
                artifacts.append({
                    "source": "Export directory (TimeDateStamp)",
                    "timestamp": exp_ts,
                    "human": _ts_str(exp_ts),
                    "type": "export_time",
                })
                # Export DLL name
                if hasattr(exp, 'name') and exp.name:
                    try:
                        exp_name = exp.name.decode('utf-8', 'ignore')
                        artifacts.append({
                            "source": "Export DLL name",
                            "value": exp_name,
                            "type": "metadata",
                        })
                    except Exception:
                        pass

        # --- 4. Resource timestamps ---
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE is not None:
            _collect_resource_timestamps(pe.DIRECTORY_ENTRY_RESOURCE, artifacts)

        # --- 5. Digital signature timestamps ---
        sig_data = pe_data.get("digital_signature", {})
        if isinstance(sig_data, dict):
            certs = sig_data.get("cryptography_parsed_certs", [])
            if isinstance(certs, list):
                for cert in certs:
                    if isinstance(cert, dict):
                        not_before = cert.get("not_valid_before_utc")
                        not_after = cert.get("not_valid_after_utc")
                        subject = cert.get("subject", "unknown")
                        if not_before:
                            artifacts.append({
                                "source": f"Certificate validity start ({subject[:40]})",
                                "value": not_before,
                                "type": "cert_time",
                            })
                        if not_after:
                            artifacts.append({
                                "source": f"Certificate validity end ({subject[:40]})",
                                "value": not_after,
                                "type": "cert_time",
                            })

        # --- 6. Rich header build info ---
        rich = pe_data.get("rich_header")
        if isinstance(rich, dict) and rich.get("decoded_values"):
            builds = rich["decoded_values"]
            if isinstance(builds, list) and builds:
                build_nums = [b.get("build_number", 0) for b in builds if isinstance(b, dict)]
                if build_nums:
                    artifacts.append({
                        "source": "Rich header (build numbers)",
                        "value": f"min={min(build_nums)}, max={max(build_nums)}, count={len(build_nums)}",
                        "type": "build_info",
                    })

        # --- 7. Anomaly detection ---
        timestamp_artifacts = [a for a in artifacts if "timestamp" in a and isinstance(a.get("timestamp"), int)]

        for a in timestamp_artifacts:
            ts = a["timestamp"]
            # Future timestamp
            if ts > now_ts + 86400:  # More than 1 day in the future
                anomalies.append({
                    "type": "future_timestamp",
                    "severity": "high",
                    "source": a["source"],
                    "description": f"Timestamp is in the future: {_ts_str(ts)}",
                })
            # Very old timestamp (before 1995)
            elif 0 < ts < 788918400:
                anomalies.append({
                    "type": "ancient_timestamp",
                    "severity": "medium",
                    "source": a["source"],
                    "description": f"Timestamp is before 1995: {_ts_str(ts)}",
                })
            # Zeroed timestamp
            elif ts == 0:
                anomalies.append({
                    "type": "zeroed_timestamp",
                    "severity": "medium",
                    "source": a["source"],
                    "description": "Timestamp is zero — likely stripped",
                })

        # Check for mismatches between PE header and debug timestamps
        if len(timestamp_artifacts) >= 2:
            pe_compile = timestamp_artifacts[0]["timestamp"]  # First is always PE header
            for a in timestamp_artifacts[1:]:
                ts = a["timestamp"]
                if ts == 0 or pe_compile == 0:
                    continue
                diff = abs(ts - pe_compile)
                # More than 1 day difference is suspicious
                if diff > 86400:
                    anomalies.append({
                        "type": "timestamp_mismatch",
                        "severity": "medium",
                        "source": a["source"],
                        "description": (
                            f"{a['source']} ({_ts_str(ts)}) differs from PE compile time "
                            f"({_ts_str(pe_compile)}) by {diff // 86400} days"
                        ),
                    })

        # Check for Delphi epoch (June 19, 1992) — indicates Delphi/Borland compiler
        delphi_epoch = 708652800
        for a in timestamp_artifacts:
            if a["timestamp"] == delphi_epoch:
                anomalies.append({
                    "type": "delphi_epoch",
                    "severity": "low",
                    "source": a["source"],
                    "description": "Timestamp matches Delphi epoch (1992-06-19) — likely compiled with Delphi/Borland",
                })

        # Sort artifacts by timestamp where available
        def _sort_key(a):
            if "timestamp" in a and isinstance(a["timestamp"], int) and a["timestamp"] > 0:
                return a["timestamp"]
            return float('inf')

        artifacts.sort(key=_sort_key)

        return {
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "pe_compile_time": _ts_str(pe_ts),
        }

    analysis = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, analysis, "unify_artifact_timeline")


_MAX_RESOURCE_ENTRIES = 1000


def _collect_resource_timestamps(resource_dir, artifacts: List, depth: int = 0, _counter: List = None):
    """Recursively collect timestamps from resource directory entries."""
    if _counter is None:
        _counter = [0]
    if depth > 3:
        return
    _counter[0] += 1
    if _counter[0] > _MAX_RESOURCE_ENTRIES:
        return
    ts = getattr(resource_dir.struct, 'TimeDateStamp', 0)
    if ts and ts != 0:
        artifacts.append({
            "source": f"Resource directory (depth {depth})",
            "timestamp": ts,
            "human": _ts_str(ts),
            "type": "resource_time",
        })
    if hasattr(resource_dir, 'entries') and resource_dir.entries:
        for entry in resource_dir.entries:
            if _counter[0] > _MAX_RESOURCE_ENTRIES:
                break
            if hasattr(entry, 'directory') and entry.directory:
                _collect_resource_timestamps(entry.directory, artifacts, depth + 1, _counter)


def _ts_str(ts: int) -> str:
    """Convert Unix timestamp to human-readable string."""
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, ValueError, OverflowError):
        return f"invalid ({ts})"
