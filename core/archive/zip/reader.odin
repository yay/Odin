package archive_zip

import "core:bufio"
import "core:bytes"
import "core:io"
import "core:os"
import "core:strings"
import "core:time"
import "core:fmt" // TODO: cleanup

Reader :: struct {
    r:             io.Reader_At,
    file:          [dynamic]^File,
    comment:       string,
    decompressors: map[u16]Decompressor,
    base_offset:   i64,
    // file_list_once: sync.Once,
    file_list:     []File_List_Entry,
}

Read_Closer :: struct {
    f:       os.Handle,
    using _: Reader,
}

File :: struct {
    using _:       File_Header,
    zip:           ^Reader,
    zipr:          io.Reader_At,
    header_offset: i64,
    zip64:         bool,
}

// A Decompressor returns a new decompressing reader, reading from r.
// The `io.Read_Closer` must be closed to release associated resources.
Decompressor :: #type proc(r: io.Reader) -> io.Read_Closer

File_List_Entry :: struct {
    name:   string,
    file:   ^File,
    is_dir: bool,
    is_dup: bool,
}

Reader_Extra_Error :: enum i32 {
	// TODO: is there a better way to combine Reader_Error and Reader_Extra_Error into a union
	// without defining a negative start value?
    Format = -10, // invalid ZIP
    Algorithm, // unsupported compression algorithm
    Checksum, // checksum error
    Comment, // invalid comment length
    Errno, // error code as defined in "core:os"
}

Reader_Error :: union #shared_nil {
    io.Error,
    Reader_Extra_Error,
}

reader_open :: proc(path: string) -> (^Read_Closer, Reader_Error) {
    f, f_err := os.open(path)
    if f_err != os.ERROR_NONE {
        return nil, .Errno
    }
    fi, fi_err := os.stat(path)
    if fi_err != os.ERROR_NONE {
        os.close(f)
        return nil, .Errno
    }
    defer os.file_info_delete(fi)

    rdr, ok := io.to_reader_at(os.stream_from_handle(f))
    if !ok {
        return nil, .Empty
    }
    r := new(Read_Closer)
    if err := reader_init(r, rdr, fi.size); err != .None {
        os.close(f)
        return nil, err
    }
    r.f = f
    return r, .None
}

reader_close :: proc(r: ^Read_Closer) {
	os.close(r.f)
    reader_destroy(r)
    free(r)
}

reader_init :: proc(r: ^Reader, rdr: io.Reader_At, size: i64) -> Reader_Error {
    end: Directory_End
    base_offset, err := read_directory_end(&end, rdr, size)
    if err != .None {
        return err
    }
    r.r = rdr
    r.base_offset = base_offset
    // Since the number of directory records is not validated, it is not
    // safe to preallocate `r.file` without first checking that the specified
    // number of files is reasonable, since a malformed archive may
    // indicate it contains up to 1 << 128 - 1 files. Since each file has a
    // header which will be _at least_ 30 bytes we can safely preallocate
    // if (data size / 30) >= end.directory_records.
    if end.directory_size < u64(size) && (u64(size) - end.directory_size) / 30 >= end.directory_records {
        r.file = make([dynamic]^File, 0, end.directory_records)
    }
    r.comment = end.comment
    rs: io.Section_Reader
    io.section_reader_init(&rs, rdr, 0, size)
    rss := io.section_reader_to_stream(&rs)
    if _, err = io.seek(rss, r.base_offset + i64(end.directory_offset), .Start); err != .None {
        return err
    }
    buf: bufio.Reader
    bufio.reader_init(&buf, rss)
    defer bufio.reader_destroy(&buf)
    // The count of files inside a ZIP is truncated to fit in a u16.
    // Gloss over this by reading headers until we encounter
    // a bad one, and then only report a .Format or .Unexpected_EOF
    // if the file count modulo 65536 is incorrect.
    for {
        f := new(File)
        f.zip = r
        f.zipr = rdr
        err = read_directory_header(f, bufio.reader_to_stream(&buf))
        if err == .Format || err == .Unexpected_EOF {
			free(f)
            break
        }
        if err != .None {
			free(f)
            return err
        }
        f.header_offset += r.base_offset
        append(&r.file, f)
    }
    if u16(len(r.file)) != u16(end.directory_records) {     // only compare 16 bits here
        // Return the read_directory_header error if we read
        // the wrong number of directory entries.
        return err
    }
    return .None
}

reader_destroy :: proc(r: ^Read_Closer) {
    for f in r.file {
        delete(f.name)
        delete(f.extra)
        delete(f.comment)
        free(f)
    }
    delete(r.file)
}

read_directory_end :: proc(
    d: ^Directory_End,
    r: io.Reader_At,
    size: i64,
) -> (
    base_offset: i64,
    err: Reader_Error,
) {
    // look for `directory_end_signature` in the last 1 KiB, then in the last 65 KiB
    buf: []byte
	defer delete(buf)
    directory_end_offset: i64
    offsets := []i64{1024, 65 * 1024}
    for offset, i in offsets {
        b_len := offset > size ? size : offset
        b := make([]byte, b_len)
		defer delete(b)
        if _, err := io.read_at(r, b, size - b_len); err != .None && err != .EOF {
            return 0, err
        }
        if p := find_signature_in_block(b); p >= 0 {
            directory_end_offset = size - b_len + i64(p)
            buf = bytes.clone(b[p + 4:]) // skip signature
            break
        }
        if i == 1 || b_len == size {
            return 0, .Format
        }
    }
	b := buf // copy `buf` to `b` as we'll be mutating the `b` with `read_uXX`` below

	// read header into struct
    d^ = Directory_End {
        disk_nbr              = u32(read_u16(&b)),
        dir_disk_nbr          = u32(read_u16(&b)),
        dir_records_this_disk = u64(read_u16(&b)),
        directory_records     = u64(read_u16(&b)),
        directory_size        = u64(read_u32(&b)),
        directory_offset      = u64(read_u32(&b)),
        comment_len           = read_u16(&b),
    }
    l := int(d.comment_len)
    if l > len(b) {
        return 0, .Comment
    }
    d.comment = string(bytes.clone(b[:l]))

    // these values mean that the file can be a zip64 file
    if d.directory_records == u64(max(u16)) || d.directory_size == u64(max(u16)) || d.directory_offset == u64(max(u32)) {
        p, err := find_directory64_end(r, directory_end_offset)
        if err == nil && p >= 0 {
            directory_end_offset = p
            err = read_directory64_end(r, p, d)
        }
        if err != nil {
            return 0, err
        }
    }

    if d.directory_size > u64(max(i64)) || d.directory_offset > u64(max(i64)) {
        return 0, .Format
    }

    base_offset = directory_end_offset - i64(d.directory_size) - i64(d.directory_offset)

    // make sure directory offset points to somewhere in our file
    if o := base_offset + i64(d.directory_offset); o < 0 || o >= size {
        return 0, .Format
    }

    // If the directory end data tells us to use a non-zero base_offset,
    // but we would find a valid directory entry, if we assume that the
    // base_offset is 0, then just use a base_offset of 0.
    // We've seen files in which the directory end data gives us
    // an incorrect base_offset.
    if base_offset > 0 {
        off := i64(d.directory_offset)
        rs: io.Section_Reader
        io.section_reader_init(&rs, r, off, size - off)
        if read_directory_header(&File{}, io.section_reader_to_stream(&rs)) == nil {
            base_offset = 0
        }
    }

    return base_offset, nil
}

read_directory_header :: proc(f: ^File, r: io.Reader) -> Reader_Error {
    buf: [directory_header_len]byte
    if _, err := io.read_full(r, buf[:]); err != nil {
        return err
    }
    b := ([]byte)(buf[:])
    if sig := read_u32(&b); sig != directory_header_signature {
        return .Format
    }
    f.creator_version = read_u16(&b)
    f.reader_version = read_u16(&b)
    f.flags = read_u16(&b)
    f.method = read_u16(&b)
    f.modified_time = read_u16(&b)
    f.modified_date = read_u16(&b)
    f.crc32 = read_u32(&b)
    f.compressed_size = read_u32(&b)
    f.uncompressed_size = read_u32(&b)
    f.compressed_size64 = u64(f.compressed_size)
    f.uncompressed_size64 = u64(f.uncompressed_size)
    filename_len := int(read_u16(&b))
    extra_len := int(read_u16(&b))
    comment_len := int(read_u16(&b))
    b = b[4:] // skip start disk number and internal attributes (2x u16)
    f.external_attrs = read_u32(&b)
    f.header_offset = i64(read_u32(&b))
    d := make([]byte, filename_len + extra_len + comment_len)
	defer delete(d)
    if _, err := io.read_full(r, d); err != nil {
        return err
    }
    f.name = strings.clone(string(d[:filename_len]))
    f.extra = bytes.clone(d[filename_len:filename_len + extra_len])
    f.comment = strings.clone(string(d[filename_len + extra_len:]))

    // Determine the character encoding.
    utf8_valid1, utf8_require1 := detect_utf8(f.name)
    utf8_valid2, utf8_require2 := detect_utf8(f.comment)
    switch {
    case !utf8_valid1 || !utf8_valid2:
        // `name` and `comment` definitely not UTF-8.
        f.non_utf8 = true
    case !utf8_require1 && !utf8_require2:
        // `name` and `comment` use only single-byte runes that overlap with UTF-8.
        f.non_utf8 = false
    case:
        // Might be UTF-8, might be some other encoding; preserve existing flag.
        // Some ZIP writers use UTF-8 encoding without setting the UTF-8 flag.
        // Since it is impossible to always distinguish valid UTF-8 from some
        // other encoding (e.g., GBK or Shift-JIS), we trust the flag.
        f.non_utf8 = f.flags & 0x800 == 0
    }

    need_uncompressed_size := f.uncompressed_size == max(u32)
    need_compressed_size := f.compressed_size == max(u32)
    need_header_offset := f.header_offset == i64(max(u32))

    // Best effort to find what we need.
    // Other ZIP authors might not even follow the basic format,
    // and we'll just ignore the `extra` content in that case.
    modified: time.Time
parse_extras:
	for extra := f.extra; len(extra) >= 4; { // need at least tag and size
		field_tag := read_u16(&extra)
		field_size := int(read_u16(&extra))
		if len(extra) < field_size {
			break
		}
		field_buf := sub(&extra, field_size)

		switch field_tag {
		case zip64_extra_id:
			f.zip64 = true
			// Update directory values from the zip64 extra block.
			// They should only be consulted if the sizes read earlier are maxed out.
			if need_uncompressed_size {
				need_uncompressed_size = false
				if len(field_buf) < 8 {
					return .Format
				}
				f.uncompressed_size64 = read_u64(&field_buf)
			}
			if need_compressed_size {
				need_compressed_size = false
				if len(field_buf) < 8 {
					return .Format
				}
				f.compressed_size64 = read_u64(&field_buf)
			}
			if need_header_offset {
				need_header_offset = false
				if len(field_buf) < 8 {
					return .Format
				}
				f.header_offset = i64(read_u64(&field_buf))
			}
		case ntfs_extra_id:
			if len(field_buf) < 4 {
				continue parse_extras
			}
			read_u32(&field_buf) // reserved (ignored)
			for len(field_buf) >= 4 {     // need at least tag and size
				attr_tag := read_u16(&field_buf)
				attr_size := int(read_u16(&field_buf))
				if len(field_buf) < attr_size {
					continue parse_extras
				}
				attr_buf := sub(&field_buf, attr_size)
				if attr_tag != 1 || attr_size != 24 {
					continue // Ignore irrelevant attributes
				}

				ticks_per_second :: 1e7 // Windows timestamp resolution
				ts := i64(read_u64(&attr_buf)) // ModTime since Windows epoch
				secs := ts / ticks_per_second
				nsecs := (1e9 / ticks_per_second) * (ts % ticks_per_second)
				epoch, ok := time.components_to_time(1601, time.Month.January, 1, 0, 0, 0, 0)
				modified = time.unix(time.time_to_unix(epoch) + secs, nsecs)
			}
		case unix_extra_id, info_zip_unix_extra_id:
			if len(field_buf) < 8 {
				continue parse_extras
			}
			read_u32(&field_buf) // AcTime (ignored)
			ts := i64(read_u32(&field_buf)) // ModTime since Unix epoch
			modified = time.unix(ts, 0)
		case ext_time_extra_id:
			if len(field_buf) < 5 || read_u8(&field_buf) & 1 == 0 {
				continue parse_extras
			}
			ts := i64(read_u32(&field_buf)) // ModTime since Unix epoch
			modified = time.unix(ts, 0)
		}
	}
    // TODO: fix time handling in this proc
    msdos_modified := msdos_time_to_time(f.modified_date, f.modified_time) // TODO: Go time.Time(2024-02-02T16:24:24Z){wall: 0, ext: 63842487864, loc: *time.Location nil}
    f.modified = msdos_modified
    if modified != (time.Time{}) {
        f.modified = modified // TODO: create an alternative for Go's modified.UTC()

        // If legacy MS-DOS timestamps are set, we can use the delta between
        // the legacy and extended versions to estimate timezone offset.
        //
        // A non-UTC timezone is always used (even if offset is zero).
        // Thus, FileHeader.Modified.Location() == time.UTC is useful for
        // determining whether extended timestamps are present.
        // This is necessary for users that need to do additional time
        // calculations when dealing with legacy ZIP formats.
        if f.modified_time != 0 || f.modified_date != 0 {
            // TODO: skipping this for now
            // f.modified = modified.In(timeZone(msdos_modified.Sub(modified)))
        }
    }

    // Assume that uncompressed size 2³²-1 could plausibly happen in
    // an old zip32 file that was sharding inputs into the largest chunks
    // possible (or is just malicious; search the web for 42.zip).
    // If `need_uncompressed_size` is true still, it means we didn't see a zip64 extension.
    // As long as the compressed size is not also 2³²-1 (implausible)
    // and the header is not also 2³²-1 (equally implausible),
    // accept the uncompressed size 2³²-1 as valid.
    // If nothing else, this keeps archive/zip working with 42.zip.
    _ = need_uncompressed_size

    if need_compressed_size || need_header_offset {
        return .Format
    }

    return .None
}

// Tries to read the zip64 locator just before the directory end
// and returns the offset of the zip64 directory end, if found.
find_directory64_end :: proc(r: io.Reader_At, directory_end_offset: i64) -> (i64, Reader_Error) {
    loc_offset := directory_end_offset - directory64_loc_len
    if loc_offset < 0 {
        return -1, nil // no need to look for a header outside the file
    }
    buf := make([]byte, directory64_loc_len)
    if _, err := io.read_at(r, buf, loc_offset); err != nil {
        return -1, err
    }
    if sig := read_u32(&buf); sig != directory64_loc_signature {
        return -1, nil
    }
    if read_u32(&buf) != 0 { // number of the disk with the start of the zip64 end of central directory
        return -1, nil // the file is not a valid zip64-file
    }
    p := read_u64(&buf) // relative offset of the zip64 end of central directory record
    if read_u32(&buf) != 1 {     // total number of disks
        return -1, nil // the file is not a valid zip64-file
    }
    return i64(p), nil
}

// Reads the zip64 directory end and updates the directory end with the zip64 directory end values.
read_directory64_end :: proc(r: io.Reader_At, offset: i64, d: ^Directory_End) -> Reader_Error {
    buf := make([]byte, directory64_end_len)
    if _, err := io.read_at(r, buf, offset); err != nil {
        return err
    }

    if sig := read_u32(&buf); sig != directory64_end_signature {
        return .Format
    }

    buf = buf[12:] // skip dir size, version and version needed (u64 + 2x u16)
    d.disk_nbr = read_u32(&buf) // number of this disk
    d.dir_disk_nbr = read_u32(&buf) // number of the disk with the start of the central directory
    d.dir_records_this_disk = read_u64(&buf) // total number of entries in the central directory on this disk
    d.directory_records = read_u64(&buf) // total number of entries in the central directory
    d.directory_size = read_u64(&buf) // size of the central directory
    d.directory_offset = read_u64(&buf) // offset of start of central directory with respect to the starting disk number

    return nil
}

find_signature_in_block :: proc(b: []byte) -> int {
    for i := len(b) - directory_end_len; i >= 0; i -= 1 {
        // defined from `directory_end_signature` in `struct.odin`
        if b[i] == 'P' && b[i + 1] == 'K' && b[i + 2] == 0x05 && b[i + 3] == 0x06 {
            comment_len := int(b[i + directory_end_len - 2]) | int(b[i + directory_end_len - 1]) << 8
            if comment_len + directory_end_len + i > len(b) {
                return -1 // truncated comment
            }
            return i
        }
    }
    return -1
}

// Following procedures read numbers from the given byte buffer in little endian order
// and advance the buffer by the number of bytes read.

read_u8 :: proc(b: ^[]byte) -> u8 {
    v := b[0]
    b^ = b[1:]
    return v
}

read_u16 :: proc(b: ^[]byte) -> u16 {
    v := u16(b[0]) | u16(b[1]) << 8
    b^ = b[2:]
    return v
}

read_u32 :: proc(b: ^[]byte) -> u32 {
    v := u32(b[0]) | u32(b[1]) << 8 | u32(b[2]) << 16 | u32(b[3]) << 24
    b^ = b[4:]
    return v
}

read_u64 :: proc(b: ^[]byte) -> u64 {
    v :=
        u64(b[0]) |
        u64(b[1]) << 8 |
        u64(b[2]) << 16 |
        u64(b[3]) << 24 |
        u64(b[4]) << 32 |
        u64(b[5]) << 40 |
        u64(b[6]) << 48 |
        u64(b[7]) << 56
    b^ = b[8:]
    return v
}

sub :: proc(b: ^[]byte, n: int) -> []byte {
    b2 := b[:n]
    b^ = b[n:]
    return b2
}

// Returns a `io.Read_Closer` that provides access to the `zip.File`'s contents.
// Multiple files may be read concurrently.
file_open :: proc(f: ^File) -> (io.Read_Closer, Reader_Error) {
	body_offset, err := file_find_body_offset(f)
	if err != .None {
		return {}, err
	}
	if strings.has_suffix(f.name, "/") {
		// The ZIP specification (APPNOTE.TXT) specifies that directories, which
		// are technically zero-byte files, must not have any associated file
		// data. We previously tried failing here if f.compressed_size64 != 0,
		// but it turns out that a number of implementations (namely, the Java
		// jar tool) don't properly set the storage method on directories
		// resulting in a file with compressed size > 0 but uncompressed size ==
		// 0. We still want to fail when a directory has associated uncompressed
		// data, but we are tolerant of cases where the uncompressed size is
		// zero but compressed size is not.
		if f.uncompressed_size64 != 0 {
			return io.Read_Closer {
				procedure = proc(stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (n: i64, err: io.Error) {
					#partial switch mode {
					case .Read:
						return 0, .Unknown // invalid format
					case .Close:
						return 0, .None
					case .Query:
						return io.query_utility({.Close, .Read, .Query})
					}
					return 0, .Empty
				},
			}, nil
		} else {
			return io.Read_Closer {
				procedure = proc(stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (n: i64, err: io.Error) {
					#partial switch mode {
					case .Read:
						return 0, .EOF
					case .Close:
						return 0, .None
					case .Query:
						return io.query_utility({.Close, .Read, .Query})
					}
					return 0, .Empty
				},
			}, nil
		}
	}

	cr := new(Checksum_Reader)
	cr.f = f

	size := i64(f.compressed_size64)
    io.section_reader_init(&cr.sr, f.zipr, f.header_offset + body_offset, size)
	dcomp := f.zip.decompressors[f.method]
	if dcomp == nil {
		return {}, .Algorithm
	}
	cr.r = dcomp(io.section_reader_to_stream(&cr.sr))

	if file_header_has_data_descriptor(f) {
		desc: File_Descriptor
		io.section_reader_init(&desc.sr, f.zipr, f.header_offset + body_offset + size, data_descriptor_len)
		desc.r = io.section_reader_to_stream(&desc.sr)
		cr.desc = desc
	}

	return checksum_reader_to_read_closer(cr), nil
}

Checksum_Reader :: struct {
	sr: io.Section_Reader,        // file body section reader
	r: io.Read_Closer,            // file body reader (backed by section reader)
	desc: Maybe(File_Descriptor), // if not nil, where to read the data descriptor
	crc:   u32,
	nread: u64,                   // number of bytes read so far
	f:     ^File,
	err:   int,                   // sticky error
}

File_Descriptor :: struct {
	sr: io.Section_Reader,        // file data descriptor section reader
	r: io.Reader,                 // file data descriptor reader (backed by section reader)
}

checksum_reader_to_read_closer :: proc(s: ^Checksum_Reader) -> (out: io.Read_Closer) {
	out.data = s
	out.procedure = _checksum_reader_proc
	return
}

@(private)
_checksum_reader_proc :: proc(stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (n: i64, err: io.Error) {
	s := (^Checksum_Reader)(stream_data)
	#partial switch mode {
	case .Close:
	case .Read:
	case .Query:
		return io.query_utility({.Close, .Read, .Query})
	}
	return 0, nil
}

file_find_body_offset :: proc(f: ^File) -> (i64, Reader_Error) {
	buf: [file_header_len]byte
	if _, err := io.read_at(f.zipr, buf[:], f.header_offset); err != .None {
		return 0, err
	}
	b := buf[:]
	if sig := read_u32(&b); sig != file_header_signature {
		return 0, .Format
	}
	b = b[22:] // skip over most of the header
	filename_len := int(read_u16(&b))
	extra_len := int(read_u16(&b))
	return i64(file_header_len + filename_len + extra_len), nil
}