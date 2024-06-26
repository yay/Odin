package archive_zip

import "core:os"
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
creator_fat   :: 0
creator_unix  :: 3
creator_ntfs  :: 11
creator_vfat  :: 14
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
zip64_extra_id         :: 0x0001 // Zip64 extended information
ntfs_extra_id          :: 0x000a // NTFS
unix_extra_id          :: 0x000d // UNIX
ext_time_extra_id      :: 0x5455 // extended timestamp
info_zip_unix_extra_id :: 0x5855 // Info-ZIP Unix extension

// FileHeader describes a file within a ZIP file.
// See ZIP specification for details: https://support.pkware.com/pkzip/appnote

File_Header :: struct {
    // `name` is the name of the file.
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

file_header_has_data_descriptor :: proc(h: ^File_Header) -> bool {
	return h.flags & 0x8 != 0
}

file_header_name :: proc(h: ^File_Header) -> string {
	return h.name
}

file_header_size :: proc(h: ^File_Header) -> i64 {
	if h.uncompressed_size64 > 0 {
		return i64(h.uncompressed_size64)
	}
	return i64(h.uncompressed_size)
}

file_header_is_dir :: proc(h: ^File_Header) -> bool {
	return file_mode_is_dir(file_header_mode(h))
}

file_header_type :: proc(h: ^File_Header) -> os.File_Mode {
	return file_mode_type(file_header_mode(h))
}

file_header_mode :: proc(h: ^File_Header) -> (mode: os.File_Mode) {
	switch h.creator_version >> 8 {
	case creator_unix, creator_macos:
		mode = unix_mode_to_file_mode(h.external_attrs >> 16)
	case creator_ntfs, creator_vfat, creator_fat:
		mode = msdos_mode_to_file_mode(h.external_attrs)
	}
	if len(h.name) > 0 && h.name[len(h.name)-1] == '/' {
		mode |= os.File_Mode_Dir // TODO: check if same as Go's fs.ModeDir
	}
	return mode
}

file_header_set_mode :: proc(h: ^File_Header, mode: os.File_Mode) {
	h.creator_version = h.creator_version & 0xff | creator_unix << 8
	h.external_attrs = file_mode_to_unix_mode(mode) << 16

	// set MSDOS attributes too, as the original zip does.
	if mode & os.File_Mode_Dir != 0 {
		h.external_attrs |= msdos_dir
	}
	if mode & 0o200 == 0 {
		h.external_attrs |= msdos_read_only
	}
}

// Unix constants. The specification doesn't mention them,
// but these seem to be the values agreed on by tools.
S_IFMT   :: 0xf000
S_IFSOCK :: 0xc000
S_IFLNK  :: 0xa000
S_IFREG  :: 0x8000
S_IFBLK  :: 0x6000
S_IFDIR  :: 0x4000
S_IFCHR  :: 0x2000
S_IFIFO  :: 0x1000
S_ISUID  :: 0x800
S_ISGID  :: 0x400
S_ISVTX  :: 0x200

msdos_dir       :: 0x10
msdos_read_only :: 0x01

file_mode_to_unix_mode :: proc(mode: os.File_Mode) -> u32 {
	m: u32
	switch mode & os.File_Mode_Type {
	case:
		m = S_IFREG
	case os.File_Mode_Dir:
		m = S_IFDIR
	case os.File_Mode_Sym_Link:
		m = S_IFLNK
	case os.File_Mode_Named_Pipe:
		m = S_IFIFO
	case os.File_Mode_Socket:
		m = S_IFSOCK
	case os.File_Mode_Device:
		m = S_IFBLK
	case os.File_Mode_Device | os.File_Mode_Char_Device:
		m = S_IFCHR
	}
	if mode & os.File_Mode_Set_User_ID != 0 {
		m |= S_ISUID
	}
	if mode & os.File_Mode_Set_Group_ID != 0 {
		m |= S_ISGID
	}
	if mode & os.File_Mode_Sticky != 0 {
		m |= S_ISVTX
	}
	return m | u32(mode & 0o777) // TODO: don't really need this?
}

unix_mode_to_file_mode :: proc(m: u32) -> os.File_Mode {
	mode := os.File_Mode(m & 0o777) // TODO: don't really need this because in Odin's File_Mode
	// the nine least-significant bits are not reserved for the standard Unix rwxrwxrwx permissions like in Go.
	switch m & S_IFMT {
	case S_IFBLK:
		mode |= os.File_Mode_Device
	case S_IFCHR:
		mode |= os.File_Mode_Device | os.File_Mode_Char_Device
	case S_IFDIR:
		mode |= os.File_Mode_Dir
	case S_IFIFO:
		mode |= os.File_Mode_Named_Pipe
	case S_IFLNK:
		mode |= os.File_Mode_Sym_Link
	case S_IFREG:
		// nothing to do
	case S_IFSOCK:
		mode |= os.File_Mode_Socket
	}
	if m & S_ISGID != 0 {
		mode |= os.File_Mode_Set_Group_ID
	}
	if m & S_ISUID != 0 {
		mode |= os.File_Mode_Set_User_ID
	}
	if m & S_ISVTX != 0 {
		mode |= os.File_Mode_Sticky
	}
	return mode
}

msdos_mode_to_file_mode :: proc(m: u32) -> (mode: os.File_Mode) {
	if m & msdos_dir != 0 {
		mode = os.File_Mode_Dir | 0o777 // TODO: don't really need this?
	} else {
		mode = 0o666
	}
	if m & msdos_read_only != 0 {
		mode &~= 0o222
	}
	return mode
}

file_mode_is_dir :: proc(m: os.File_Mode) -> bool {
	return m & os.File_Mode_Dir != 0
}

file_mode_type :: proc(m: os.File_Mode) -> os.File_Mode {
	return m & os.File_Mode_Type
}