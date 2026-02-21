"""Resource management: PEiD database and Capa rules download/extraction."""
import hashlib
import os
import zipfile
import shutil

from pathlib import Path
from typing import Optional

from pemcp.config import (
    logger, REQUESTS_AVAILABLE, CAPA_RULES_SUBDIR_NAME,
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
        response = requests.get(url, timeout=15); response.raise_for_status()
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
        response = requests.get(rules_zip_url, timeout=60, stream=True)
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
