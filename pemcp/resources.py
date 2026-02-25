"""Resource management: PEiD database, Capa rules, and YARA rules download/extraction."""
import hashlib
import os
import zipfile
import shutil

from pathlib import Path
from typing import Optional, List

from pemcp.config import (
    logger, REQUESTS_AVAILABLE, CAPA_RULES_SUBDIR_NAME,
    DATA_DIR, YARA_RULES_STORE_DIR_NAME,
    YARA_REVERSINGLABS_ZIP_URL, YARA_REVERSINGLABS_SUBDIR,
    YARA_COMMUNITY_ZIP_URL, YARA_COMMUNITY_SUBDIR,
    HTTP_DOWNLOAD_TIMEOUT, HTTP_QUICK_TIMEOUT,
)
from pemcp.utils import safe_print

if REQUESTS_AVAILABLE:
    import requests

# Expected SHA256 checksums for pinned resource downloads.
# Update these when bumping the URLs in config.py.
_EXPECTED_CHECKSUMS: dict = {
    # Add sha256 hex digests here when known, keyed by download URL.
    # e.g. "https://...capa-rules-v9.3.0.zip": "abcdef...",
}


def _verify_download_checksum(filepath: str, url: str) -> bool:
    """Verify a downloaded file against a pinned SHA256 checksum, if available.

    Returns True if the checksum matches or no checksum is pinned for this URL.
    Returns False if the checksum is pinned but does not match.
    """
    expected = _EXPECTED_CHECKSUMS.get(url)
    if expected is None:
        return True  # No pinned checksum — accept the download
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    actual = sha256.hexdigest()
    if actual != expected:
        logger.error(
            "Checksum mismatch for %s: expected %s..., "
            "got %s... — the download may be corrupt or tampered.",
            url, expected[:16], actual[:16]
        )
        return False
    logger.info("Checksum verified for download: %s", os.path.basename(filepath))
    return True


def ensure_peid_db_exists(url: str, local_path: str, verbose: bool = False) -> bool:
    if os.path.exists(local_path):
        if verbose: safe_print(f"   [VERBOSE] PEiD database already exists at: {local_path}", verbose_prefix=" ")
        return True
    if not REQUESTS_AVAILABLE:
        safe_print("[!] 'requests' library not found. Cannot download PEiD database.", verbose_prefix=" ")
        return False
    safe_print(f"[*] PEiD database not found at {local_path}. Attempting download from {url}...", verbose_prefix=" ")
    try:
        response = requests.get(url, timeout=HTTP_QUICK_TIMEOUT); response.raise_for_status()
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, 'wb') as f: f.write(response.content)
        if not _verify_download_checksum(local_path, url):
            os.remove(local_path)
            return False
        safe_print(f"[*] PEiD database successfully downloaded to: {local_path}", verbose_prefix=" ")
        return True
    except requests.exceptions.RequestException as e:
        safe_print(f"[!] Error downloading PEiD database: {e}", verbose_prefix=" ")
        if os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass
        return False
    except IOError as e:
        safe_print(f"[!] Error saving PEiD database to {local_path}: {e}", verbose_prefix=" ")
        return False

def ensure_capa_rules_exist(rules_base_dir: str, rules_zip_url: str, verbose: bool = False) -> Optional[str]:
    final_rules_target_path = os.path.join(rules_base_dir, CAPA_RULES_SUBDIR_NAME)

    if os.path.isdir(final_rules_target_path) and os.listdir(final_rules_target_path):
        if verbose: logger.info("Capa rules already available at: %s", final_rules_target_path)
        return final_rules_target_path

    if not REQUESTS_AVAILABLE:
        logger.error("'requests' library not found. Cannot download capa rules.")
        return None

    logger.info("Capa rules not found at '%s'. Attempting to download and extract to '%s'...", final_rules_target_path, rules_base_dir)

    os.makedirs(rules_base_dir, exist_ok=True)
    zip_path = os.path.join(rules_base_dir, "capa-rules.zip")
    extracted_top_level_dir_path = None

    try:
        logger.info("Downloading capa rules from %s to %s...", rules_zip_url, zip_path)
        response = requests.get(rules_zip_url, timeout=HTTP_DOWNLOAD_TIMEOUT, stream=True)
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info("Capa rules zip downloaded successfully.")

        if not _verify_download_checksum(zip_path, rules_zip_url):
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return None

        logger.info("Extracting capa rules from %s into %s...", zip_path, rules_base_dir)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Validate member paths to prevent zip-slip attacks
            target_dir = os.path.realpath(rules_base_dir)
            for member in zip_ref.namelist():
                member_path = os.path.realpath(os.path.join(rules_base_dir, member))
                if not member_path.startswith(target_dir + os.sep) and member_path != target_dir:
                    raise zipfile.BadZipFile(f"Zip member '{member}' would extract outside target directory (path traversal).")
            zip_ref.extractall(rules_base_dir)
        logger.info("Capa rules extracted successfully from zip.")

        extracted_dir_name_found = None
        expected_prefix = "capa-rules-" # Default prefix for capa-rules releases
        # Try to find the directory that starts with the expected prefix.
        # GitHub zip files usually create a top-level directory like 'capa-rules-vX.Y.Z'.
        for item in os.listdir(rules_base_dir):
            if item.startswith(expected_prefix) and os.path.isdir(os.path.join(rules_base_dir, item)):
                extracted_dir_name_found = item
                break

        # If not found with prefix, try to find *any* directory that contains a 'rules' subdir
        # This is a fallback for differently structured zips, though less common for capa-rules.
        if not extracted_dir_name_found:
            for item in os.listdir(rules_base_dir):
                potential_path = os.path.join(rules_base_dir, item)
                if os.path.isdir(potential_path) and os.path.isdir(os.path.join(potential_path, CAPA_RULES_SUBDIR_NAME)):
                    extracted_dir_name_found = item # The parent dir of 'rules'
                    # In this case, the 'rules' subdir is already what we want, or we need to move its contents.
                    # For simplicity, let's assume if we find 'item/rules', we want 'item/rules'
                    # The original logic moves 'item' to 'final_rules_target_path' if 'item' is 'capa-rules-X.Y.Z'
                    # If 'item' is just 'rules', then we might need to adjust.
                    # The current logic expects to move the *container* of the rules.
                    # If the zip extracts directly as 'rules', this needs adjustment.
                    # However, capa-rules zips from GitHub are `capa-rules-TAG/rules/...`
                    break


        if not extracted_dir_name_found:
            logger.error("Could not find the main '%s*' directory or a directory containing '%s' within '%s' after extraction. Contents: %s", expected_prefix, CAPA_RULES_SUBDIR_NAME, rules_base_dir, os.listdir(rules_base_dir))
            if os.path.exists(zip_path):
                try: os.remove(zip_path)
                except OSError: pass
            return None

        extracted_top_level_dir_path = os.path.join(rules_base_dir, extracted_dir_name_found)

        # Determine the actual source of rules: either the extracted_top_level_dir_path itself (if it's the 'rules' dir)
        # or the 'rules' subdirectory within it.
        source_rules_content_path = extracted_top_level_dir_path
        if os.path.isdir(os.path.join(extracted_top_level_dir_path, CAPA_RULES_SUBDIR_NAME)):
            source_rules_content_path = os.path.join(extracted_top_level_dir_path, CAPA_RULES_SUBDIR_NAME)
            logger.info("Found rules content within subdirectory: %s", source_rules_content_path)
        else:
             logger.info("Using extracted directory as rules content source: %s", source_rules_content_path)


        if os.path.exists(final_rules_target_path):
            logger.warning("Target rules directory '%s' already exists. Removing it before placing newly extracted rules.", final_rules_target_path)
            try:
                shutil.rmtree(final_rules_target_path)
            except Exception as e_rm:
                logger.error("Failed to remove existing target rules directory '%s': %s", final_rules_target_path, e_rm)
                if os.path.isdir(extracted_top_level_dir_path): # Clean up the originally extracted folder
                    try: shutil.rmtree(extracted_top_level_dir_path)
                    except Exception: logger.debug("Cleanup of extracted dir failed", exc_info=True)
                if os.path.exists(zip_path):
                    try: os.remove(zip_path)
                    except OSError: pass
                return None

        logger.info("Moving rules from '%s' to '%s'...", source_rules_content_path, final_rules_target_path)
        try:
            # shutil.move might fail if src is a subdir of a dir we want to remove later.
            # It's safer to copy and then remove the original extracted structure.
            shutil.copytree(source_rules_content_path, final_rules_target_path)
            logger.info("Successfully copied rules to '%s'.", final_rules_target_path)
        except Exception as e_mv_cp: # Changed from move to copytree
            logger.error("Failed to copy rules from '%s' to '%s': %s", source_rules_content_path, final_rules_target_path, e_mv_cp)
            # Clean up potentially partially copied target
            if os.path.isdir(final_rules_target_path):
                try: shutil.rmtree(final_rules_target_path)
                except Exception: logger.debug("Cleanup of target dir failed", exc_info=True)
            # Clean up the originally extracted folder in any case
            if os.path.isdir(extracted_top_level_dir_path):
                try: shutil.rmtree(extracted_top_level_dir_path)
                except Exception: logger.debug("Cleanup of extracted dir failed", exc_info=True)
            if os.path.exists(zip_path):
                try: os.remove(zip_path)
                except OSError: pass
            return None
        finally:
            # Clean up the entire originally extracted top-level directory after successful copy
            if os.path.isdir(extracted_top_level_dir_path):
                try:
                    shutil.rmtree(extracted_top_level_dir_path)
                    logger.info("Cleaned up temporary extraction directory: %s", extracted_top_level_dir_path)
                except Exception as e_rm_extracted:
                    logger.warning("Could not remove temporary extraction directory %s: %s", extracted_top_level_dir_path, e_rm_extracted)


        if os.path.isdir(final_rules_target_path) and os.listdir(final_rules_target_path):
            logger.info("Capa rules now correctly organized at: %s", final_rules_target_path)
            return final_rules_target_path
        else:
            logger.error("Capa rules were processed, but the final target directory '%s' is still not found or is empty.", final_rules_target_path)
            if os.path.exists(zip_path): # Ensure zip is removed if process failed here
                try: os.remove(zip_path)
                except OSError: pass
            return None

    except requests.exceptions.RequestException as e:
        logger.error("Error downloading capa rules: %s", e)
    except zipfile.BadZipFile:
        logger.error("Error: Downloaded capa rules file '%s' is not a valid zip file or is corrupted.", zip_path)
    except Exception as e:
        logger.error("An unexpected error occurred during capa rules download/extraction/organization: %s", e, exc_info=verbose)
        if extracted_top_level_dir_path and os.path.isdir(extracted_top_level_dir_path): # If top level was created
            try: shutil.rmtree(extracted_top_level_dir_path) # Clean it up
            except Exception: logger.debug("Cleanup of extracted dir failed", exc_info=True)
    finally:
        if os.path.exists(zip_path):
            try: os.remove(zip_path)
            except OSError as e_rm_zip: logger.warning("Could not remove downloaded zip %s: %s", zip_path, e_rm_zip)
    return None


# ---------------------------------------------------------------------------
# YARA Rules Store
# ---------------------------------------------------------------------------

def _download_and_extract_yara_source(
    zip_url: str,
    target_dir: str,
    zip_prefix_hint: str,
    verbose: bool = False,
) -> bool:
    """Download a YARA rules ZIP and extract it into *target_dir*.

    Returns True on success, False on failure.
    """
    if os.path.isdir(target_dir) and any(
        f.endswith(('.yar', '.yara'))
        for _d, _ds, fs in os.walk(target_dir)
        for f in fs
    ):
        if verbose:
            logger.info("YARA rules already present at: %s", target_dir)
        return True

    if not REQUESTS_AVAILABLE:
        logger.error("'requests' library not found. Cannot download YARA rules from %s.", zip_url)
        return False

    logger.info("Downloading YARA rules from %s ...", zip_url)
    zip_path = target_dir + ".zip"
    try:
        response = requests.get(zip_url, timeout=HTTP_DOWNLOAD_TIMEOUT, stream=True)
        response.raise_for_status()
        os.makedirs(os.path.dirname(zip_path) or ".", exist_ok=True)
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        if not _verify_download_checksum(zip_path, zip_url):
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return False

        # Extract to a temp location next to target
        extract_tmp = target_dir + "_extract_tmp"
        if os.path.isdir(extract_tmp):
            shutil.rmtree(extract_tmp)
        os.makedirs(extract_tmp, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Validate member paths to prevent zip-slip
            real_tmp = os.path.realpath(extract_tmp)
            for member in zf.namelist():
                member_path = os.path.realpath(os.path.join(extract_tmp, member))
                if not member_path.startswith(real_tmp + os.sep) and member_path != real_tmp:
                    raise zipfile.BadZipFile(
                        f"Zip member '{member}' would extract outside target directory (path traversal)."
                    )
            zf.extractall(extract_tmp)

        # Find the top-level extracted directory (GitHub zips always have one)
        extracted_dirs = [
            d for d in os.listdir(extract_tmp)
            if os.path.isdir(os.path.join(extract_tmp, d))
        ]
        if not extracted_dirs:
            logger.error("No directories found after extracting %s", zip_url)
            shutil.rmtree(extract_tmp, ignore_errors=True)
            return False

        # Pick the directory matching the hint, or just use the first one
        source_dir = None
        for d in extracted_dirs:
            if d.startswith(zip_prefix_hint):
                source_dir = os.path.join(extract_tmp, d)
                break
        if source_dir is None:
            source_dir = os.path.join(extract_tmp, extracted_dirs[0])

        # Move into final target
        if os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        shutil.copytree(source_dir, target_dir)
        logger.info("YARA rules extracted to: %s", target_dir)
        return True

    except requests.exceptions.RequestException as e:
        logger.error("Error downloading YARA rules from %s: %s", zip_url, e)
    except zipfile.BadZipFile as e:
        logger.error("Downloaded YARA archive is not a valid zip: %s", e)
    except Exception as e:
        logger.error("Unexpected error during YARA rules download/extraction: %s", e, exc_info=verbose)
    finally:
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except OSError:
                pass
        extract_tmp = target_dir + "_extract_tmp"
        if os.path.isdir(extract_tmp):
            shutil.rmtree(extract_tmp, ignore_errors=True)
    return False


def ensure_yara_rules_exist(verbose: bool = False) -> Optional[str]:
    """Ensure the YARA rules store exists, downloading sources if needed.

    Downloads two rule sets:
    - **ReversingLabs** (MIT licence) — general-purpose malware YARA rules.
    - **Yara-Rules Community** (GPL-2.0) — crowd-sourced rules covering
      packers, crypto, anti-debug/VM, capabilities, malware families, etc.

    Returns the path to the *yara_rules_store* directory on success, or
    None if no rules could be obtained.
    """
    store_dir = str(DATA_DIR / YARA_RULES_STORE_DIR_NAME)
    os.makedirs(store_dir, exist_ok=True)

    rl_dir = os.path.join(store_dir, YARA_REVERSINGLABS_SUBDIR)
    community_dir = os.path.join(store_dir, YARA_COMMUNITY_SUBDIR)

    rl_ok = _download_and_extract_yara_source(
        YARA_REVERSINGLABS_ZIP_URL, rl_dir,
        zip_prefix_hint="reversinglabs-yara-rules",
        verbose=verbose,
    )
    community_ok = _download_and_extract_yara_source(
        YARA_COMMUNITY_ZIP_URL, community_dir,
        zip_prefix_hint="rules-",
        verbose=verbose,
    )

    if rl_ok or community_ok:
        return store_dir
    return None


def get_default_yara_rules_path() -> Optional[str]:
    """Return the default YARA rules store path if it contains any rules.

    Does NOT trigger a download — call :func:`ensure_yara_rules_exist` first
    if you want to populate the store.
    """
    store = DATA_DIR / YARA_RULES_STORE_DIR_NAME
    if not store.is_dir():
        return None
    # Quick check: at least one .yar or .yara file anywhere in the store
    for ext in ("*.yar", "*.yara"):
        try:
            next(store.rglob(ext))
            return str(store)
        except StopIteration:
            continue
    return None
