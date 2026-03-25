"""MCP tools for VBA/XLM macro analysis in Office documents.

Provides analysis capabilities for OLE2 and OOXML documents containing
VBA macros, Excel 4.0 (XLM) macros, and embedded OLE objects.
"""
import asyncio
import logging
import os
import re
from typing import Any, Dict, List

from arkana.config import Context
from arkana.imports import OLETOOLS_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _get_filepath, _check_lib

logger = logging.getLogger("Arkana")

# Limits
_MAX_MACRO_SOURCES = 50
_MAX_SUSPICIOUS_KEYWORDS = 200
_MAX_XLM_FORMULAS = 500
_MACRO_CODE_PREVIEW_LEN = 500

# Auto-execute trigger names (case-insensitive matching)
_AUTO_EXEC_TRIGGERS = {
    "autoopen", "autoclose", "autoexec", "autonew", "autoexit",
    "document_open", "document_close", "document_new",
    "workbook_open", "workbook_close", "workbook_activate",
    "workbook_beforesave", "workbook_beforeclose",
    "auto_open", "auto_close",
}

# Obfuscation indicator functions
_OBFUSCATION_INDICATORS = [
    "chr", "chrw", "chrb", "asc", "ascw",
    "replace", "strreverse", "mid", "left", "right",
    "callbyname", "execute", "executeglobal",
    "eval", "clng", "cbyte",
]

# XLM-specific dangerous formulas
_XLM_DANGEROUS_PATTERNS = [
    "EXEC", "CALL", "FORMULA", "REGISTER", "RUN",
    "HALT", "SET.VALUE", "CHAR", "ALERT",
    "FOPEN", "FWRITE", "FCLOSE", "FREAD",
    "FILES", "DIRECTORY", "APP.MAXIMIZE",
    "WHILE", "NEXT", "GOTO", "RETURN",
    "GET.WORKSPACE", "GET.WINDOW", "GET.CELL",
    "WAIT", "NOW", "DAY",
]

# IOC regex patterns for macro code
_IOC_URL_RE = re.compile(
    r'https?://[^\s"\'<>\)\]}{,]{4,200}',
    re.IGNORECASE,
)
_IOC_IP_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
)
_IOC_FILEPATH_RE = re.compile(
    r'(?:[A-Za-z]:\\[^\s"\'<>|]{2,200}|\\\\[^\s"\'<>|]{2,200})',
)


def _check_oletools(tool_name: str):
    """Guard: ensure oletools is installed."""
    _check_lib("oletools", OLETOOLS_AVAILABLE, tool_name)


def _extract_iocs_from_code(code: str) -> Dict[str, List[str]]:
    """Extract IOCs (URLs, IPs, file paths) from macro source code."""
    iocs: Dict[str, List[str]] = {}

    urls = list(set(_IOC_URL_RE.findall(code)))
    if urls:
        iocs["urls"] = urls[:50]

    ips = list(set(_IOC_IP_RE.findall(code)))
    # Filter out common non-routable / version-like patterns
    real_ips = []
    for ip in ips:
        parts = ip.split(".")
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            continue
        if all(0 <= o <= 255 for o in octets):
            # Skip 0.x.x.x, 127.x.x.x, and common version-like strings
            if octets[0] not in (0, 127):
                real_ips.append(ip)
    if real_ips:
        iocs["ip_addresses"] = real_ips[:50]

    paths = list(set(_IOC_FILEPATH_RE.findall(code)))
    if paths:
        iocs["file_paths"] = paths[:50]

    return iocs


def _compute_obfuscation_score(code: str) -> int:
    """Compute an obfuscation score (0-100) based on indicator function density."""
    if not code:
        return 0

    code_lower = code.lower()
    total_chars = len(code_lower)
    if total_chars == 0:
        return 0

    indicator_count = 0
    for indicator in _OBFUSCATION_INDICATORS:
        indicator_count += code_lower.count(indicator + "(")

    # Density: indicator calls per 1000 characters
    density = (indicator_count / total_chars) * 1000

    # Also check for string concatenation patterns (common in obfuscation)
    concat_count = code_lower.count('" & "') + code_lower.count('" + "')
    concat_density = (concat_count / total_chars) * 1000

    # Score: scale density to 0-100
    score = min(100, int(density * 15 + concat_density * 10))

    # Bonus for specific high-confidence obfuscation patterns
    if "chrw(" in code_lower or "chrb(" in code_lower:
        score = min(100, score + 10)
    if "strreverse(" in code_lower:
        score = min(100, score + 10)
    if "callbyname" in code_lower:
        score = min(100, score + 15)
    if "executeglobal" in code_lower or "execute(" in code_lower:
        score = min(100, score + 10)

    return score


@tool_decorator
async def analyze_office_macros(
    ctx: Context,
    file_path: str = "",
) -> Dict[str, Any]:
    """Analyze VBA macros in Office documents (DOC, DOCM, XLS, XLSM, PPT, etc.).

    Phase: 1 -- Identify

    Extracts and analyzes VBA macro source code, identifies auto-execute
    triggers, suspicious keywords (Shell, CreateObject, Environ), obfuscation
    indicators, and potential IOCs within macro code.

    Args:
        file_path: Path to the Office document. Uses loaded file if empty.
    """
    _check_oletools("analyze_office_macros")
    await ctx.info("Analyzing VBA macros in Office document")

    target = _get_filepath(file_path)

    def _analyze() -> Dict[str, Any]:
        from oletools.olevba import VBA_Parser

        vba_parser = None
        try:
            vba_parser = VBA_Parser(target)

            if not vba_parser.detect_vba_macros():
                return {
                    "file": os.path.basename(target),
                    "macros_found": False,
                    "summary": "No VBA macros detected in this document.",
                }

            # Extract macro source code
            macros: List[Dict[str, Any]] = []
            all_code = ""
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_all_macros():
                code_str = vba_code if isinstance(vba_code, str) else str(vba_code)
                all_code += code_str + "\n"
                preview = code_str[:_MACRO_CODE_PREVIEW_LEN]
                if len(code_str) > _MACRO_CODE_PREVIEW_LEN:
                    preview += f"\n... [{len(code_str) - _MACRO_CODE_PREVIEW_LEN} more chars]"
                entry: Dict[str, Any] = {
                    "filename": str(vba_filename) if vba_filename else str(filename),
                    "stream_path": str(stream_path) if stream_path else "",
                    "vba_code_preview": preview,
                    "code_length": len(code_str),
                }
                macros.append(entry)
                if len(macros) >= _MAX_MACRO_SOURCES:
                    break

            # Analyze macros for suspicious keywords
            suspicious_keywords: List[Dict[str, str]] = []
            auto_exec_triggers: List[str] = []
            try:
                results = vba_parser.analyze_macros()
                for kw_type, keyword, description in results:
                    kw_type_str = str(kw_type) if kw_type else ""
                    keyword_str = str(keyword) if keyword else ""
                    desc_str = str(description) if description else ""

                    # Detect auto-exec triggers
                    if kw_type_str.lower() in ("autoexec", "auto_exec"):
                        if keyword_str not in auto_exec_triggers:
                            auto_exec_triggers.append(keyword_str)

                    suspicious_keywords.append({
                        "keyword": keyword_str,
                        "type": kw_type_str,
                        "description": desc_str,
                    })
                    if len(suspicious_keywords) >= _MAX_SUSPICIOUS_KEYWORDS:
                        break
            except Exception as exc:
                logger.warning("oletools analyze_macros failed: %s", exc)

            # Also scan code for auto-exec triggers by name
            code_lower = all_code.lower()
            for trigger in _AUTO_EXEC_TRIGGERS:
                if trigger in code_lower and trigger not in [t.lower() for t in auto_exec_triggers]:
                    # Find the actual-case version in the code
                    auto_exec_triggers.append(trigger)

            # Extract IOCs
            iocs = _extract_iocs_from_code(all_code)

            # Compute obfuscation score
            obfuscation_score = _compute_obfuscation_score(all_code)

            # Build summary
            risk_parts = []
            if auto_exec_triggers:
                risk_parts.append(f"{len(auto_exec_triggers)} auto-exec trigger(s)")
            if suspicious_keywords:
                risk_parts.append(f"{len(suspicious_keywords)} suspicious keyword(s)")
            if iocs:
                ioc_count = sum(len(v) for v in iocs.values())
                risk_parts.append(f"{ioc_count} IOC(s)")
            if obfuscation_score >= 50:
                risk_parts.append("high obfuscation")
            elif obfuscation_score >= 20:
                risk_parts.append("moderate obfuscation")

            if risk_parts:
                summary = f"VBA macros found with {', '.join(risk_parts)}."
            else:
                summary = f"{len(macros)} VBA macro(s) found, no suspicious indicators detected."

            result: Dict[str, Any] = {
                "file": os.path.basename(target),
                "macros_found": True,
                "macro_count": len(macros),
                "macros": macros,
                "summary": summary,
            }
            if auto_exec_triggers:
                result["auto_exec_triggers"] = auto_exec_triggers
            if suspicious_keywords:
                result["suspicious_keywords"] = suspicious_keywords
            if iocs:
                result["iocs"] = iocs
            result["obfuscation_score"] = obfuscation_score

            return result

        except Exception as exc:
            return {
                "error": f"Failed to analyze macros: {exc}",
                "hint": "Ensure the file is a valid Office document (OLE2 or OOXML).",
            }
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass

    result = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, result, "analyze_office_macros", "macro source previews")


@tool_decorator
async def detect_xlm_macros(
    ctx: Context,
    file_path: str = "",
) -> Dict[str, Any]:
    """Detect Excel 4.0 (XLM) macros in Excel documents.

    Phase: 1 -- Identify

    Scans for Excel 4.0 macro sheets and extracts cell formulas that may
    contain malicious EXEC, CALL, FORMULA, or RUN patterns.

    Args:
        file_path: Path to the Excel document. Uses loaded file if empty.
    """
    _check_oletools("detect_xlm_macros")
    await ctx.info("Scanning for Excel 4.0 (XLM) macros")

    target = _get_filepath(file_path)

    def _detect() -> Dict[str, Any]:
        from oletools.olevba import VBA_Parser

        vba_parser = None
        try:
            vba_parser = VBA_Parser(target)

            has_macros = vba_parser.detect_vba_macros()

            # Extract all macros and look for XLM indicators
            xlm_formulas: List[Dict[str, Any]] = []
            vba_macros_found = False

            if has_macros:
                for (_filename, stream_path, _vba_filename, vba_code) in vba_parser.extract_all_macros():
                    code_str = vba_code if isinstance(vba_code, str) else str(vba_code)
                    stream_str = str(stream_path) if stream_path else ""

                    # XLM macros typically appear in macro sheets
                    is_xlm_stream = any(
                        tag in stream_str.lower()
                        for tag in ("xlm_macro", "macro", "xl4", "excel 4.0")
                    )

                    if not is_xlm_stream:
                        # Also check code content for XLM-style cell formulas
                        # XLM formulas often start with = or contain XLM function names
                        has_xlm_content = False
                        for pattern in _XLM_DANGEROUS_PATTERNS:
                            if pattern in code_str.upper():
                                has_xlm_content = True
                                break
                        if not has_xlm_content:
                            vba_macros_found = True
                            continue

                    # Parse individual formulas/lines
                    for line_num, line in enumerate(code_str.splitlines(), 1):
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue

                        matched_patterns = []
                        line_upper = line_stripped.upper()
                        for pattern in _XLM_DANGEROUS_PATTERNS:
                            if pattern in line_upper:
                                matched_patterns.append(pattern)

                        if matched_patterns:
                            entry: Dict[str, Any] = {
                                "formula": line_stripped[:300],
                                "line": line_num,
                                "stream": stream_str,
                                "matched_patterns": matched_patterns,
                            }
                            xlm_formulas.append(entry)
                            if len(xlm_formulas) >= _MAX_XLM_FORMULAS:
                                break

                    if len(xlm_formulas) >= _MAX_XLM_FORMULAS:
                        break

            if not xlm_formulas:
                return {
                    "file": os.path.basename(target),
                    "xlm_macros_found": False,
                    "vba_macros_present": vba_macros_found,
                    "summary": "No Excel 4.0 (XLM) macros detected."
                            + (" VBA macros are present -- use analyze_office_macros() for analysis."
                               if vba_macros_found else ""),
                }

            # Risk assessment based on pattern matches
            dangerous_count = 0
            pattern_counts: Dict[str, int] = {}
            for formula in xlm_formulas:
                for pat in formula.get("matched_patterns", []):
                    pattern_counts[pat] = pattern_counts.get(pat, 0) + 1
                    if pat in ("EXEC", "CALL", "REGISTER", "RUN"):
                        dangerous_count += 1

            if dangerous_count > 5:
                risk = "HIGH"
                risk_detail = f"{dangerous_count} execution-related formulas found"
            elif dangerous_count > 0:
                risk = "MEDIUM"
                risk_detail = f"{dangerous_count} execution-related formula(s) found"
            else:
                risk = "LOW"
                risk_detail = "XLM formulas found but no direct execution patterns"

            result: Dict[str, Any] = {
                "file": os.path.basename(target),
                "xlm_macros_found": True,
                "formula_count": len(xlm_formulas),
                "formulas": xlm_formulas,
                "pattern_summary": pattern_counts,
                "risk_level": risk,
                "risk_detail": risk_detail,
                "vba_macros_present": vba_macros_found,
                "summary": f"{len(xlm_formulas)} XLM formula(s) detected, risk: {risk} -- {risk_detail}.",
            }

            return result

        except Exception as exc:
            return {
                "error": f"Failed to scan for XLM macros: {exc}",
                "hint": "Ensure the file is a valid Excel document (XLS, XLSM, XLSB).",
            }
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass

    result = await asyncio.to_thread(_detect)
    return await _check_mcp_response_size(ctx, result, "detect_xlm_macros", "the formula list")


@tool_decorator
async def analyze_ole_streams(
    ctx: Context,
    file_path: str = "",
) -> Dict[str, Any]:
    """Analyze OLE2 compound file structure and identify suspicious streams.

    Phase: 1 -- Identify

    Examines the OLE2 container structure to identify embedded objects,
    suspicious stream names, encrypted content, and file properties.

    Args:
        file_path: Path to the OLE2 document. Uses loaded file if empty.
    """
    _check_oletools("analyze_ole_streams")
    await ctx.info("Analyzing OLE2 stream structure")

    target = _get_filepath(file_path)

    def _analyze() -> Dict[str, Any]:
        from oletools.oleid import OleID

        try:
            oid = OleID(target)
            indicators_raw = oid.check()

            indicators: List[Dict[str, Any]] = []
            vba_macros_present = False
            xlm_macros_present = False
            encrypted = False
            flash_objects = False
            embedded_files = False

            for indicator in indicators_raw:
                name = str(getattr(indicator, "name", "")) if hasattr(indicator, "name") else str(indicator)
                value = getattr(indicator, "value", None)
                risk = str(getattr(indicator, "risk", "info")).lower() if hasattr(indicator, "risk") else "info"
                description = str(getattr(indicator, "description", "")) if hasattr(indicator, "description") else ""

                # Normalize value for display
                if value is None:
                    value_str = "N/A"
                elif isinstance(value, bool):
                    value_str = str(value)
                elif isinstance(value, (list, tuple)):
                    value_str = ", ".join(str(v) for v in value) if value else "none"
                else:
                    value_str = str(value)

                entry: Dict[str, Any] = {
                    "name": name,
                    "value": value_str,
                    "risk": risk,
                }
                if description:
                    entry["description"] = description

                indicators.append(entry)

                # Detect specific properties
                name_lower = name.lower()
                value_lower = value_str.lower() if isinstance(value_str, str) else ""

                if "vba" in name_lower and value_lower not in ("false", "no", "0", "none", "n/a"):
                    vba_macros_present = True
                if "xlm" in name_lower and value_lower not in ("false", "no", "0", "none", "n/a"):
                    xlm_macros_present = True
                if "encrypt" in name_lower and value_lower not in ("false", "no", "0", "none", "n/a"):
                    encrypted = True
                if "flash" in name_lower and value_lower not in ("false", "no", "0", "none", "n/a"):
                    flash_objects = True
                if ("external" in name_lower or "object" in name_lower) and value_lower not in ("false", "no", "0", "none", "n/a"):
                    embedded_files = True

            # Build summary
            findings = []
            if vba_macros_present:
                findings.append("VBA macros")
            if xlm_macros_present:
                findings.append("XLM macros")
            if encrypted:
                findings.append("encryption")
            if flash_objects:
                findings.append("Flash objects")
            if embedded_files:
                findings.append("embedded objects")

            # Count risk levels
            high_risk_count = sum(1 for i in indicators if i.get("risk") in ("high", "critical"))
            medium_risk_count = sum(1 for i in indicators if i.get("risk") == "medium")

            if high_risk_count > 0:
                summary = f"HIGH RISK: {high_risk_count} high-risk indicator(s) found"
                if findings:
                    summary += f" ({', '.join(findings)})"
                summary += "."
            elif medium_risk_count > 0:
                summary = f"MEDIUM RISK: {medium_risk_count} medium-risk indicator(s)"
                if findings:
                    summary += f" ({', '.join(findings)})"
                summary += "."
            elif findings:
                summary = f"Indicators found: {', '.join(findings)}."
            else:
                summary = "No suspicious indicators detected in OLE2 structure."

            result: Dict[str, Any] = {
                "file": os.path.basename(target),
                "indicator_count": len(indicators),
                "indicators": indicators,
                "vba_macros_present": vba_macros_present,
                "xlm_macros_present": xlm_macros_present,
                "encrypted": encrypted,
                "flash_objects": flash_objects,
                "embedded_files": embedded_files,
                "summary": summary,
            }

            return result

        except Exception as exc:
            return {
                "error": f"Failed to analyze OLE2 streams: {exc}",
                "hint": "Ensure the file is a valid OLE2 compound document (DOC, XLS, PPT, etc.).",
            }

    result = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, result, "analyze_ole_streams", "the indicator list")
