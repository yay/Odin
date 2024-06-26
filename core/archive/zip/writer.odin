package archive_zip

import "core:unicode/utf8"

// Reports whether s is a valid UTF-8 string, and whether the string
// must be considered UTF-8 encoding (i.e., not compatible with CP-437, ASCII,
// or any other common encoding).
detect_utf8 :: proc(s: string) -> (valid, require: bool) {
	for i := 0; i < len(s); {
		r, size := utf8.decode_rune_in_string(s[i:])
		i += size
		// Officially, ZIP uses CP-437, but many readers use the system's
		// local character encoding. Most encoding are compatible with a large
		// subset of CP-437, which itself is ASCII-like.
		//
		// Forbid 0x7e and 0x5c since EUC-KR and Shift-JIS replace those
		// characters with localized currency and overline characters.
		if r < 0x20 || r > 0x7d || r == 0x5c {
			if !utf8.valid_rune(r) || (r == utf8.RUNE_ERROR && size == 1) {
				return false, false
			}
			require = true
		}
	}
	return true, require
}