def _xor_bytes(data: bytes, key_bytes: bytes) -> bytes:
    """Helper function to perform XOR on a byte string with a key of any length."""
    key_len = len(key_bytes)
    if key_len == 0:
        return data
    return bytes([data[i] ^ key_bytes[i % key_len] for i in range(len(data))])

def _extract_staged_payloads(data: bytes, ctx: Optional[Context] = None, loop: Optional[asyncio.AbstractEventLoop] = None) -> List[Tuple[str, bytes]]:
    """
    Scans data for a common 4-byte XOR stager pattern and decodes the payload.
    This pattern consists of a header [type][payload_size][xor_key][id] followed by the payload.
    This version includes more robust checks to find embedded PE files.
    """
    staged_payloads = []
    header_format = '<IIII' # payload_type, payload_size, xor_key, id2
    header_size = struct.calcsize(header_format)

    for i in range(len(data) - header_size):
        try:
            payload_type, payload_size, xor_key, id2 = struct.unpack(header_format, data[i:i+header_size])

            if xor_key == 0 or not (4096 < payload_size < len(data)):
                continue
            
            payload_start = i + header_size
            if payload_start + payload_size > len(data):
                continue

            encrypted_payload = data[payload_start : payload_start + payload_size]
            xor_key_bytes = struct.pack('<I', xor_key)
            
            decoded_payload = _xor_bytes(encrypted_payload, xor_key_bytes)

            # --- BUG FIX ---
            # Instead of a strict startswith, find the MZ header near the beginning.
            # Some packers add a few bytes of junk before the PE.
            mz_offset = decoded_payload.find(b'MZ')
            
            # Check if 'MZ' is found and is within the first few bytes (e.g., 16)
            if mz_offset != -1 and mz_offset < 16:
                location_desc = f"Staged PE Payload (found at offset 0x{i:x}, key 0x{xor_key:x}, size 0x{payload_size:x})"
                # --- ASYNC BUG FIX ---
                # Pass the main event loop to the thread to safely call async functions.
                if ctx and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(ctx.info(f"Config Hunter: Found potential staged payload at offset 0x{i:x}"), loop)
                
                # Append the *trimmed* payload, starting from the MZ header.
                staged_payloads.append((location_desc, decoded_payload[mz_offset:]))

        except struct.error:
            continue
            
    return staged_payloads

def _parse_config_from_profile(data: bytes, profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parses a decrypted data blob according to a dynamically constructed configuration profile.
    """
    parsed_config = {}
    endian_char = '>' if profile.get('structure_definition', {}).get('endian', 'big') == 'big' else '<'
    fields = profile.get('structure_definition', {}).get('fields', [])
    field_map = {field['id']: field for field in fields}

    offset = 0
    try:
        while offset < len(data) - 6: 
            setting_id_raw, data_type_raw, length = struct.unpack(f'{endian_char}HHH', data[offset:offset+6])
            offset += 6

            setting_id_str = f"{setting_id_raw:04x}"

            if setting_id_raw == 0:
                break 

            if setting_id_str not in field_map:
                offset += length
                continue

            field_def = field_map[setting_id_str]
            field_name = field_def['name']
            field_type = field_def['type']
            value_data = data[offset:offset+length]
            offset += length

            if field_type == 'short':
                parsed_config[field_name] = struct.unpack(f'{endian_char}H', value_data)[0]
            elif field_type == 'integer':
                parsed_config[field_name] = struct.unpack(f'{endian_char}I', value_data)[0]
            elif field_type == 'string':
                parsed_config[field_name] = value_data.split(b'\x00', 1)[0].decode('utf-8', 'ignore')
            elif field_type == 'bytes':
                parsed_config[field_name] = value_data.hex()
            elif field_type == 'raw_bytes':
                 parsed_config[field_name] = value_data
            else:
                parsed_config[field_name] = value_data.hex()

    except (struct.error, IndexError) as e:
        logger.warning(f"Config Hunter: Error parsing structure at offset {offset}: {e}")
        return None

    return parsed_config

@tool_decorator
async def find_generic_c2_config(
   ctx: Context,
   validation_pattern_hex: str,
   structure_definition_fields: List[Dict[str, str]],
   endianness: str = 'big',
   known_xor_keys_hex: Optional[List[str]] = None,
   entropy_threshold: float = 7.0,
   search_pe_overlay: bool = True,
   bruteforce_all_keys: bool = True,
   limit_scan_to_section: Optional[str] = None
) -> Dict[str, Any]:
   """
   Finds and decodes a hidden C2 configuration, with robust support for packed/staged payloads.

   This tool is designed for maximum flexibility. Instead of using a static profile, it accepts
   the core components of a configuration profile as direct arguments. This allows an LLM
   to define and hunt for custom C2 structures on the fly without complex JSON escaping.

   Args:
       ctx: The MCP Context object.
       validation_pattern_hex: Hex string of magic bytes appearing at the start of a decrypted config.
       structure_definition_fields: List of dicts defining the config fields.
                                    Each must have 'id' (hex), 'name' (str), 'type' (str).
       endianness: Endianness of the data ('big' or 'little'). Defaults to 'big'.
       known_xor_keys_hex: (Optional) List of known single-byte XOR keys (hex strings) to test first.
       entropy_threshold: Minimum entropy for a section to be scanned. Defaults to 7.0.
       search_pe_overlay: If True, scans data appended to the PE file. Defaults to True.
       bruteforce_all_keys: If True, tests all 256 single-byte XOR keys. Defaults to True.
       limit_scan_to_section: (Optional) If set, ONLY the specified section from the original PE is
                              added to the candidate list (staged payloads are still added).

   Returns:
       A dictionary with the decoded configuration and discovery metadata, or a status message.

   Example Usage for Cobalt Strike v4:
   ```python
   find_generic_c2_config(
       validation_pattern_hex='000100010002',
       known_xor_keys_hex=['69', '2e'],
       bruteforce_all_keys=True,
       structure_definition_fields=[
         {"id": "0001", "name": "BeaconType", "type": "short"},
         {"id": "0002", "name": "Port", "type": "short"},
         {"id": "0003", "name": "SleepTime", "type": "integer"},
         {"id": "0004", "name": "MaxGetSize", "type": "integer"},
         {"id": "0005", "name": "Jitter", "type": "short"},
         {"id": "0007", "name": "PublicKey", "type": "bytes"},
         {"id": "0008", "name": "C2Server", "type": "string"},
         {"id": "0009", "name": "UserAgent", "type": "string"},
         {"id": "000a", "name": "HttpPostUri", "type": "string"},
         {"id": "000b", "name": "Malleable_C2_Instructions", "type": "raw_bytes"},
         {"id": "001a", "name": "HttpGetVerb", "type": "string"},
         {"id": "001b", "name": "HttpPostVerb", "type": "string"},
         {"id": "001d", "name": "SpawnTo_x86", "type": "string"},
         {"id": "001e", "name": "SpawnTo_x64", "type": "string"},
         {"id": "0025", "name": "Watermark", "type": "integer"}
       ]
   )
   ```
   """
   await ctx.info("Starting generic C2 config hunter with stager-aware logic.")
   if PE_OBJECT_FOR_MCP is None:
       raise RuntimeError("No PE file loaded. Cannot perform configuration analysis.")

   try:
       profile = {
           "validation_pattern": {"value": validation_pattern_hex},
           "known_xor_keys": known_xor_keys_hex or [],
           "structure_definition": {"endian": endianness, "fields": structure_definition_fields}
       }
       validation_bytes = bytes.fromhex(validation_pattern_hex)
   except (ValueError, TypeError) as e:
       raise ValueError(f"Invalid dynamic profile parameters: {e}")

   candidate_blocks: List[Tuple[str, bytes]] = []

   await ctx.info("Performing pre-scan for known stager patterns...")
   loop = asyncio.get_running_loop()
   staged_payloads = await asyncio.to_thread(_extract_staged_payloads, PE_OBJECT_FOR_MCP.__data__, ctx, loop)
   
   if staged_payloads:
       await ctx.info(f"Found {len(staged_payloads)} potential staged payload(s). Adding their sections to scan candidates.")
       for desc, payload_data in staged_payloads:
           try:
               embedded_pe = pefile.PE(data=payload_data)
               for section in embedded_pe.sections:
                   section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                   candidate_blocks.append((f"{desc} -> Section '{section_name}'", section.get_data()))
           except pefile.PEFormatError:
               candidate_blocks.append((f"{desc} (raw blob)", payload_data))
   
   if limit_scan_to_section:
       await ctx.info(f"Adding user-specified section '{limit_scan_to_section}' from original PE to candidates.")
       section_found = False
       for section in PE_OBJECT_FOR_MCP.sections:
           if section.Name.decode('utf-8', 'ignore').strip('\x00') == limit_scan_to_section:
               candidate_blocks.append((f"Original PE -> Section '{limit_scan_to_section}'", section.get_data()))
               section_found = True
               break
       if not section_found and not staged_payloads:
           return {"status": "error", "message": f"Section '{limit_scan_to_section}' not found and no staged payloads detected."}
   else:
       await ctx.info(f"Adding high-entropy sections and overlay from original PE to candidates.")
       for section in PE_OBJECT_FOR_MCP.sections:
           if section.get_entropy() > entropy_threshold:
               section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
               candidate_blocks.append((f"Original PE -> Section '{section_name}' (Entropy: {section.get_entropy():.2f})", section.get_data()))
       if search_pe_overlay:
           overlay_data = PE_OBJECT_FOR_MCP.get_overlay()
           if overlay_data:
               candidate_blocks.append(("Original PE -> Overlay", overlay_data))

   if not candidate_blocks:
       return {"status": "not_found", "message": "No candidate blocks (staged, high-entropy, or overlay) found to scan."}

   keys_to_test = []
   if profile.get('known_xor_keys'):
       keys_to_test.extend([int(k, 16) for k in profile['known_xor_keys']])
   if bruteforce_all_keys:
       keys_to_test.extend(list(set(range(256)) - set(keys_to_test)))

   await ctx.info(f"Scanning {len(candidate_blocks)} total candidate block(s) with {len(keys_to_test)} single-byte XOR key(s).")

   for location_desc, data_block in candidate_blocks:
       for key in keys_to_test:
           decrypted_data = _xor_bytes(data_block, bytes([key]))
           
           # --- BUG FIX ---
           # The config isn't always at the start. Search for the pattern within the block.
           config_offset = decrypted_data.find(validation_bytes)
           
           if config_offset != -1:
               await ctx.info(f"Validation pattern found in '{location_desc}' with key 0x{key:02x} at offset 0x{config_offset:x}.")
               
               # Parse the config starting from the found offset.
               found_config = _parse_config_from_profile(decrypted_data[config_offset:], profile)
               
               if found_config:
                   return {
                       "status": "success",
                       "profile_name": "DynamicProfile",
                       "discovery_metadata": {
                           "found_in": location_desc,
                           "block_offset_of_config": f"0x{config_offset:x}",
                           "decryption_key_hex": f"{key:02x}"
                       },
                       "decoded_config": found_config
                   }
               else:
                    await ctx.warning(f"Validation pattern matched but failed to parse structure in '{location_desc}' with key 0x{key:02x}.")

   return {"status": "not_found", "message": "Scanned all candidate blocks but no matching configuration was found."}