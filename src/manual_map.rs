#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::slice;

use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject,
    LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS,
};

use crate::codes;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _r: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    _time_date_stamp: u32,
    _ptr_sym: u32,
    _num_sym: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    _maj_link: u8,
    _min_link: u8,
    _size_code: u32,
    _size_init: u32,
    _size_uninit: u32,
    address_of_entry_point: u32,
    _base_code: u32,
    image_base: u64,
    _section_align: u32,
    _file_align: u32,
    _maj_os: u16,
    _min_os: u16,
    _maj_img: u16,
    _min_img: u16,
    _maj_sub: u16,
    _min_sub: u16,
    _w32_ver: u32,
    size_of_image: u32,
    size_of_headers: u32,
    _checksum: u32,
    _subsystem: u16,
    _dll_characteristics: u16,
    _stack_res: u64,
    _stack_com: u64,
    _heap_res: u64,
    _heap_com: u64,
    _loader_flags: u32,
    _num_rva: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader {
    _name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _ptr_relocs: u32,
    _ptr_lines: u32,
    _num_relocs: u16,
    _num_lines: u16,
    characteristics: u32,
}

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    _time_date_stamp: u32,
    _forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[rustfmt::skip]
const STAGE2: [u8; 190] = [
    0x53,
    0x55,
    0x56,
    0x57,
    0x41, 0x54,
    0x41, 0x55,
    0x41, 0x56,
    0x41, 0x57,
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0x89, 0xCE,
    0x48, 0x8B, 0x3E,
    0x4C, 0x8B, 0x66, 0x08,
    0x4C, 0x8B, 0x6E, 0x10,
    0x48, 0x8B, 0x5E, 0x20,
    0x44, 0x8B, 0x76, 0x28,
    0x45, 0x31, 0xFF,
    0x48, 0x31, 0xED,
    0x4D, 0x85, 0xF6,
    0x0F, 0x84, 0x58, 0x00, 0x00, 0x00,
    0x8B, 0x43, 0x0C,
    0x44, 0x39, 0xF8,
    0x0F, 0x84, 0x1B, 0x00, 0x00, 0x00,
    0x8B, 0x03,
    0x48, 0x89, 0xF9,
    0x48, 0x01, 0xC1,
    0x41, 0xFF, 0xD4,
    0x48, 0x85, 0xC0,
    0x0F, 0x84, 0x2B, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xC5,
    0x44, 0x8B, 0x7B, 0x0C,
    0x8B, 0x43, 0x04,
    0x85, 0xC0,
    0x78, 0x0C,
    0x48, 0x89, 0xFA,
    0x48, 0x01, 0xC2,
    0x48, 0x83, 0xC2, 0x02,
    0xEB, 0x04,
    0x48, 0x0F, 0xB7, 0xD0,
    0x48, 0x89, 0xE9,
    0x41, 0xFF, 0xD5,
    0x8B, 0x4B, 0x08,
    0x48, 0x89, 0x04, 0x0F,
    0x48, 0x83, 0xC3, 0x10,
    0x49, 0xFF, 0xCE,
    0x0F, 0x85, 0xA8, 0xFF, 0xFF, 0xFF,
    0x48, 0x8B, 0x46, 0x18,
    0x48, 0x85, 0xC0,
    0x74, 0x12,
    0x48, 0x89, 0xF9,
    0xBA, 0x01, 0x00, 0x00, 0x00,
    0x4D, 0x31, 0xC0,
    0xFF, 0xD0,
    0x0F, 0xB6, 0xC0,
    0xEB, 0x05,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x28,
    0x41, 0x5F,
    0x41, 0x5E,
    0x41, 0x5D,
    0x41, 0x5C,
    0x5F,
    0x5E,
    0x5D,
    0x5B,
    0xC3,
];

#[repr(C)]
struct Stage2Param {
    image_base: u64,
    load_library_a: u64,
    get_proc_address: u64,
    dll_main: u64,
    patches_addr: u64,
    patches_count: u32,
    _pad: u32,
}

#[repr(C)]
struct ImportPatch {
    dll_name_rva: u32,
    func_kind_value: u32,
    iat_slot_rva: u32,
    dll_id: u32,
}

pub fn inject(pid: u32, bytes: &[u8], _flags: u32) -> Result<(), i32> {
    if bytes.len() < mem::size_of::<ImageDosHeader>() {
        return Err(codes::E_PE_PARSE);
    }
    let dos = unsafe { &*(bytes.as_ptr() as *const ImageDosHeader) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(codes::E_PE_PARSE);
    }
    let nt_off = dos.e_lfanew as usize;
    if nt_off + mem::size_of::<ImageNtHeaders64>() > bytes.len() {
        return Err(codes::E_PE_PARSE);
    }
    let nt = unsafe { &*(bytes.as_ptr().add(nt_off) as *const ImageNtHeaders64) };
    if nt.signature != IMAGE_NT_SIGNATURE
        || nt.optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err(codes::E_PE_PARSE);
    }

    let image_size = nt.optional_header.size_of_image as usize;
    let preferred_base = nt.optional_header.image_base;
    let entry_rva = nt.optional_header.address_of_entry_point as usize;

    let (load_library_a, get_proc_address) = unsafe { resolve_kernel32_helpers()? };

    let target: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }
        .map_err(|_| codes::E_OPEN_PROCESS)?;
    let _guard_target = HandleGuard(target);

    let remote_image = unsafe {
        VirtualAllocEx(
            target,
            None,
            image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if remote_image.is_null() {
        return Err(codes::E_ALLOC);
    }
    let remote_image_addr = remote_image as u64;
    let mut remote_image_guard = RemoteAllocGuard {
        handle: target,
        base: remote_image,
    };

    let mut local_image = vec![0u8; image_size];
    let headers_size = nt.optional_header.size_of_headers as usize;
    if headers_size > bytes.len() || headers_size > image_size {
        return Err(codes::E_PE_PARSE);
    }
    local_image[..headers_size].copy_from_slice(&bytes[..headers_size]);

    let num_sections = nt.file_header.number_of_sections as usize;
    let sh_off = nt_off
        + mem::size_of::<u32>()
        + mem::size_of::<ImageFileHeader>()
        + nt.file_header.size_of_optional_header as usize;
    if sh_off + num_sections * mem::size_of::<ImageSectionHeader>() > bytes.len() {
        return Err(codes::E_PE_PARSE);
    }
    let sections = unsafe {
        slice::from_raw_parts(
            bytes.as_ptr().add(sh_off) as *const ImageSectionHeader,
            num_sections,
        )
    };
    for s in sections {
        let raw = s.pointer_to_raw_data as usize;
        let raw_sz = s.size_of_raw_data as usize;
        let va = s.virtual_address as usize;
        if raw_sz == 0 {
            continue;
        }
        if raw + raw_sz > bytes.len() || va + raw_sz > image_size {
            return Err(codes::E_PE_PARSE);
        }
        local_image[va..va + raw_sz].copy_from_slice(&bytes[raw..raw + raw_sz]);
    }

    let delta = remote_image_addr.wrapping_sub(preferred_base);
    if delta != 0 {
        unsafe { apply_relocs(local_image.as_mut_ptr(), image_size, nt, delta)? };
    }

    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            target,
            remote_image,
            local_image.as_ptr() as *const c_void,
            image_size,
            Some(&mut written),
        )
    };
    if ok.is_err() || written != image_size {
        return Err(codes::E_WRITE);
    }

    let patches = unsafe { build_patch_table(&local_image, nt)? };

    let stage2_off: usize = 0;
    let param_off: usize = round_up(STAGE2.len(), 16);
    let patches_off: usize = round_up(param_off + mem::size_of::<Stage2Param>(), 16);
    let patches_size: usize = patches.len() * mem::size_of::<ImportPatch>();
    let helper_size: usize = round_up(patches_off + patches_size, 16).max(4096);

    let helper = unsafe {
        VirtualAllocEx(
            target,
            None,
            helper_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if helper.is_null() {
        return Err(codes::E_ALLOC);
    }
    let mut helper_guard = RemoteAllocGuard {
        handle: target,
        base: helper,
    };
    let helper_addr = helper as u64;

    let mut helper_buf = vec![0u8; helper_size];
    helper_buf[stage2_off..stage2_off + STAGE2.len()].copy_from_slice(&STAGE2);

    let param = Stage2Param {
        image_base: remote_image_addr,
        load_library_a,
        get_proc_address,
        dll_main: if entry_rva != 0 {
            remote_image_addr + entry_rva as u64
        } else {
            0
        },
        patches_addr: helper_addr + patches_off as u64,
        patches_count: patches.len() as u32,
        _pad: 0,
    };
    unsafe {
        ptr::copy_nonoverlapping(
            &param as *const Stage2Param as *const u8,
            helper_buf.as_mut_ptr().add(param_off),
            mem::size_of::<Stage2Param>(),
        );
        if patches_size > 0 {
            ptr::copy_nonoverlapping(
                patches.as_ptr() as *const u8,
                helper_buf.as_mut_ptr().add(patches_off),
                patches_size,
            );
        }
    }

    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            target,
            helper,
            helper_buf.as_ptr() as *const c_void,
            helper_size,
            Some(&mut written),
        )
    };
    if ok.is_err() || written != helper_size {
        return Err(codes::E_WRITE);
    }

    let start: LPTHREAD_START_ROUTINE =
        unsafe { Some(mem::transmute(helper.add(stage2_off))) };
    let param_addr = unsafe { helper.add(param_off) };
    let mut tid: u32 = 0;
    let thread = unsafe {
        CreateRemoteThread(
            target,
            None,
            0,
            start,
            Some(param_addr as *const c_void),
            0,
            Some(&mut tid),
        )
    }
    .map_err(|_| codes::E_THREAD)?;
    let _guard_thread = HandleGuard(thread);

    let wait = unsafe { WaitForSingleObject(thread, 30_000) };
    if wait != WAIT_OBJECT_0 {
        return Err(codes::E_THREAD);
    }
    let mut rc: u32 = 0;
    unsafe { GetExitCodeThread(thread, &mut rc) }.map_err(|_| codes::E_THREAD)?;
    if rc == 0 {
        return Err(codes::E_REMOTE_RC);
    }

    unsafe {
        let _ = VirtualFreeEx(target, helper, 0, MEM_RELEASE);
    }
    helper_guard.disarm();
    remote_image_guard.disarm();
    Ok(())
}

fn round_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

unsafe fn resolve_kernel32_helpers() -> Result<(u64, u64), i32> {
    let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr()))
        .map_err(|_| codes::E_BAD_INPUT)?;
    if k32.is_invalid() {
        return Err(codes::E_BAD_INPUT);
    }
    let ll = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr()));
    let gp = GetProcAddress(k32, PCSTR(b"GetProcAddress\0".as_ptr()));
    match (ll, gp) {
        (Some(l), Some(g)) => Ok((l as usize as u64, g as usize as u64)),
        _ => Err(codes::E_BAD_INPUT),
    }
}

unsafe fn apply_relocs(
    base: *mut u8,
    image_size: usize,
    nt: &ImageNtHeaders64,
    delta: u64,
) -> Result<(), i32> {
    let dir = nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(());
    }
    let start = base.add(dir.virtual_address as usize);
    let end = start.add(dir.size as usize);
    let mut p = start;
    while (p as usize) + mem::size_of::<ImageBaseRelocation>() <= end as usize {
        let block = &*(p as *const ImageBaseRelocation);
        if block.size_of_block < mem::size_of::<ImageBaseRelocation>() as u32 {
            break;
        }
        let count = (block.size_of_block as usize - mem::size_of::<ImageBaseRelocation>())
            / mem::size_of::<u16>();
        let entries = p.add(mem::size_of::<ImageBaseRelocation>()) as *const u16;
        for i in 0..count {
            let entry = *entries.add(i);
            let kind = entry >> 12;
            let offset = entry & 0x0fff;
            let target_rva = block.virtual_address as usize + offset as usize;
            if target_rva >= image_size {
                continue;
            }
            let t = base.add(target_rva);
            match kind {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_HIGHLOW => {
                    let p32 = t as *mut u32;
                    *p32 = (*p32).wrapping_add(delta as u32);
                }
                IMAGE_REL_BASED_DIR64 => {
                    let p64 = t as *mut u64;
                    *p64 = (*p64).wrapping_add(delta);
                }
                _ => return Err(codes::E_PE_PARSE),
            }
        }
        p = p.add(block.size_of_block as usize);
    }
    Ok(())
}

unsafe fn build_patch_table(
    local_image: &[u8],
    nt: &ImageNtHeaders64,
) -> Result<Vec<ImportPatch>, i32> {
    let dir = nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(Vec::new());
    }
    let base = local_image.as_ptr();
    let mut out = Vec::new();
    let mut imp =
        base.add(dir.virtual_address as usize) as *const ImageImportDescriptor;
    let mut dll_id: u32 = 0;
    loop {
        let desc = &*imp;
        if desc.name == 0 && desc.first_thunk == 0 {
            break;
        }
        dll_id += 1;

        let lookup_rva = if desc.original_first_thunk != 0 {
            desc.original_first_thunk
        } else {
            desc.first_thunk
        };
        let mut lookup = base.add(lookup_rva as usize) as *const u64;
        let mut iat_rva = desc.first_thunk;
        loop {
            let entry = *lookup;
            if entry == 0 {
                break;
            }
            let func_kind_value: u32 = if entry & IMAGE_ORDINAL_FLAG64 != 0 {
                0x8000_0000 | ((entry & 0xffff) as u32)
            } else {
                entry as u32
            };
            out.push(ImportPatch {
                dll_name_rva: desc.name,
                func_kind_value,
                iat_slot_rva: iat_rva,
                dll_id,
            });
            lookup = lookup.add(1);
            iat_rva += 8;
        }

        imp = imp.add(1);
    }
    Ok(out)
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct RemoteAllocGuard {
    handle: HANDLE,
    base: *mut c_void,
}
impl RemoteAllocGuard {
    fn disarm(&mut self) {
        self.base = ptr::null_mut();
    }
}
impl Drop for RemoteAllocGuard {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                let _ = VirtualFreeEx(self.handle, self.base, 0, MEM_RELEASE);
            }
        }
    }
}
