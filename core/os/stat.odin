package os

import "core:time"

File_Info :: struct {
	fullpath: string, // allocated
	name:     string, // uses `fullpath` as underlying data
	size:     i64,
	mode:     File_Mode,
	is_dir:   bool,
	creation_time:     time.Time,
	modification_time: time.Time,
	access_time:       time.Time,
}

file_info_slice_delete :: proc(infos: []File_Info, allocator := context.allocator) {
	for i := len(infos)-1; i >= 0; i -= 1 {
		file_info_delete(infos[i], allocator)
	}
	delete(infos, allocator)
}

file_info_delete :: proc(fi: File_Info, allocator := context.allocator) {
	delete(fi.fullpath, allocator)
}

File_Mode :: distinct u32

File_Mode_Dir          :: File_Mode(1<<16)
File_Mode_Named_Pipe   :: File_Mode(1<<17)
File_Mode_Device       :: File_Mode(1<<18)
File_Mode_Char_Device  :: File_Mode(1<<19)
File_Mode_Sym_Link     :: File_Mode(1<<20)
File_Mode_Socket       :: File_Mode(1<<21)
File_Mode_Set_User_ID  :: File_Mode(1<<22)
File_Mode_Set_Group_ID :: File_Mode(1<<23)
File_Mode_Sticky       :: File_Mode(1<<24)
File_Mode_Irregular    :: File_Mode(1<<25)
// Mask for the type bits. For regular files, none will be set.
File_Mode_Type         :: File_Mode_Dir | File_Mode_Sym_Link | File_Mode_Named_Pipe | File_Mode_Socket | File_Mode_Device | File_Mode_Char_Device | File_Mode_Irregular