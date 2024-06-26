package archive_zip

import "core:time"

file_header_signature :: 0x04034b50
directory_header_signature :: 0x02014b50
directory_end_signature :: 0x06054b50
directory64_loc_signature :: 0x07064b50
directory64_end_signature :: 0x06064b50
data_descriptor_signature :: 0x08074b50 // de-facto standard; required by OS X Finder
file_header_len :: 30 // + filename + extra
directory_header_len :: 46 // + filename + extra + comment
directory_end_len :: 22 // + comment
data_descriptor_len :: 16 // four uint32: descriptor signature, crc32, compressed size, size
data_descriptor64_len :: 24 // two uint32: signature, crc32 | two uint64: compressed size, size
directory64_loc_len :: 20 //
directory64_end_len :: 56 // + extra

// Constants for the first byte in CreatorVersion.
creator_fat :: 0
creator_unix :: 3
creator_ntfs :: 11
creator_vfat :: 14
creator_macos :: 19

// Version numbers.
zip_version_20 :: 20 // 2.0
zip_version_45 :: 45 // 4.5 (reads and writes zip64 archives)

// Limits for non zip64 files.
uint16max :: (1 << 16) - 1
uint32max :: (1 << 32) - 1

// Extra header IDs.
//
// IDs 0..31 are reserved for official use by PKWARE.
// IDs above that range are defined by third-party vendors.
// Since ZIP lacked high precision timestamps (nor an official specification
// of the timezone used for the date fields), many competing extra fields
// have been invented. Pervasive use effectively makes them "official".
//
// See http://mdfs.net/Docs/Comp/Archiving/Zip/ExtraField
zip64_extra_id :: 0x0001 // Zip64 extended information
ntfs_extra_id :: 0x000a // NTFS
unix_extra_id :: 0x000d // UNIX
ext_time_extra_id :: 0x5455 // extended timestamp
info_zip_unix_extra_id :: 0x5855 // Info-ZIP Unix extension

// FileHeader describes a file within a ZIP file.
// See the [ZIP specification] for details.
//
// [ZIP specification]: https://support.pkware.com/pkzip/appnote
File_Header :: struct {
    // `name` is the name of the file.
    //
    // It must be a relative path, not start with a drive letter (such as "C:"),
    // and must use forward slashes instead of back slashes. A trailing slash
    // indicates that this file is a directory and should have no data.
    name:                string,
    // `comment` is any arbitrary user-defined string shorter than 64KiB.
    comment:             string,
    // `non_utf8` indicates that Name and Comment are not encoded in UTF-8.
    //
    // By specification, the only other encoding permitted should be CP-437,
    // but historically many ZIP readers interpret Name and Comment as whatever
    // the system's local character encoding happens to be.
    //
    // This flag should only be set if the user intends to encode a non-portable
    // ZIP file for a specific localized region. Otherwise, the Writer
    // automatically sets the ZIP format's UTF-8 flag for valid UTF-8 strings.
    non_utf8:            bool,
    creator_version:     u16,
    reader_version:      u16,
    flags:               u16,
    // `method` is the compression method. If zero, Store is used.
    method:              u16,
    // `modified` is the modified time of the file.
    //
    // When reading, an extended timestamp is preferred over the legacy MS-DOS
    // date field, and the offset between the times is used as the timezone.
    // If only the MS-DOS date is present, the timezone is assumed to be UTC.
    //
    // When writing, an extended timestamp (which is timezone-agnostic) is
    // always emitted. The legacy MS-DOS date field is encoded according to the
    // location of the Modified time.
    modified:            time.Time,
    // `modified_time` is an MS-DOS-encoded time.
    //
    // Deprecated: Use `modified` instead.
    modified_time:       u16, // deprecated
    // `modified_date` is an MS-DOS-encoded date.
    //
    // Deprecated: Use `modified` instead.
    modified_date:       u16, // deprecated
    // `crc32` is the CRC32 checksum of the file content.
    crc32:               u32,
    // `compressed_size` is the compressed size of the file in bytes.
    // If either the uncompressed or compressed size of the file
    // does not fit in 32 bits, `compressed_size` is set to `max(u32)`.
    //
    // Deprecated: Use `compressed_size64` instead.
    compressed_size:     u32, // deprecated
    // `uncompressed_size` is the compressed size of the file in bytes.
    // If either the uncompressed or compressed size of the file
    // does not fit in 32 bits, CompressedSize is set to `max(u32)`.
    //
    // Deprecated: Use UncompressedSize64 instead.
    uncompressed_size:   u32, // deprecated
    // `compressed_size64` is the compressed size of the file in bytes.
    compressed_size64:   u64,
    // `uncompressed_size64` is the uncompressed size of the file in bytes.
    uncompressed_size64: u64,
    extra:               []byte,
    external_attrs:      u32, // Meaning depends on `creator_version`
}

Directory_End :: struct {
    disk_nbr:              u32, // unused
    dir_disk_nbr:          u32, // unused
    dir_records_this_disk: u64, // unused
    directory_records:     u64,
    directory_size:        u64,
    directory_offset:      u64, // relative to file
    comment_len:           u16,
    comment:               string,
}

// Converts an MS-DOS date and time into a time.Time. The resolution is 2s.
// See: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
msdos_time_to_time :: proc(dos_date, dos_time: u16) -> time.Time {
    // date bits 0-4: day of month; 5-8: month; 9-15: years since 1980
    // time bits 0-4: second/2; 5-10: minute; 11-15: hour
    t, ok := time.components_to_time(
        int(dos_date >> 9 + 1980),
        time.Month(dos_date >> 5 & 0xf),
        int(dos_date & 0x1f),
        int(dos_time >> 11),
        int(dos_time >> 5 & 0x3f),
        int(dos_time & 0x1f * 2),
        0, // nanoseconds
		// UTC location implied
    )
	if !ok { // TODO: retunr (time.Time, bool) from msdos_time_to_time
		return time.Time{}
	}
	return t
}
