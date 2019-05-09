#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include <common.h>
#include <iokit.h>
#include <patchfinder64.h>
#include <sys/mount.h>
#include <libproc.h>

#include "KernelMemory.h"
#include "KernelStructureOffsets.h"
#include "KernelUtilities.h"
#include "find_port.h"
#include "KernelExecution.h"
#include "pac.h"
#include "kernel_call.h"

#define off_OSDictionary_SetObjectWithCharP (sizeof(void*) * 0x1F)
#define off_OSDictionary_GetObjectWithCharP (sizeof(void*) * 0x26)
#define off_OSDictionary_Merge (sizeof(void*) * 0x23)
#define off_OSArray_Merge (sizeof(void*) * 0x1E)
#define off_OSArray_RemoveObject (sizeof(void*) * 0x20)
#define off_OSArray_GetObject (sizeof(void*) * 0x22)
#define off_OSObject_Release (sizeof(void*) * 0x05)
#define off_OSObject_GetRetainCount (sizeof(void*) * 0x03)
#define off_OSObject_Retain (sizeof(void*) * 0x04)
#define off_OSString_GetLength (sizeof(void*) * 0x11)

#define P_MEMSTAT_INTERNAL 0x00001000 /* Process is a system-critical-not-be-jetsammed process i.e. launchd */

#define CS_VALID 0x0000001 /* dynamically valid */
#define CS_GET_TASK_ALLOW 0x0000004 /* has get-task-allow entitlement */
#define CS_INSTALLER 0x0000008 /* has installer entitlement */
#define CS_HARD 0x0000100 /* don't load invalid pages */
#define CS_KILL 0x0000200 /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION 0x0000400 /* force expiration checking */
#define CS_RESTRICT 0x0000800 /* tell dyld to treat restricted */
#define CS_REQUIRE_LV 0x0002000 /* require library validation */
#define CS_KILLED 0x1000000 /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM 0x2000000 /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY 0x4000000 /* this is a platform binary */
#define CS_DEBUGGED 0x10000000 /* process is currently or has previously been debugged and allowed to run with invalid pages */

#define TF_PLATFORM 0x00000400 /* task is a platform binary */

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4

#define CS_OPS_STATUS 0
#define CS_OPS_ENTITLEMENTS_BLOB 7
#define FILE_EXC_KEY "com.apple.security.exception.files.absolute-path.read-only"

const char *abs_path_exceptions[] = {
    "/Library",
    "/private/var/mobile/Library",
    "/System/Library/Caches",
    "/private/var/mnt",
    NULL
};

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

extern char *get_path_for_pid(pid_t pid);

kptr_t kernel_base = KPTR_NULL;
kptr_t offset_options = KPTR_NULL;
bool found_offsets = false;

kptr_t cached_task_self_addr = KPTR_NULL;
kptr_t task_self_addr()
{
    if (!KERN_POINTER_VALID(cached_task_self_addr)) {
        cached_task_self_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), mach_task_self()) : find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
        LOG("task self: " ADDR, cached_task_self_addr);
    }
    return cached_task_self_addr;
}

kptr_t ipc_space_kernel()
{
    return ReadKernel64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

kptr_t current_thread()
{
    auto thread = mach_thread_self();
    auto thread_port = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), thread) : find_port_address(thread, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), thread);
    thread = THREAD_NULL;
    return ReadKernel64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

kptr_t find_kernel_base()
{
    auto host = mach_host_self();
    auto hostport_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), host) : find_port_address(host, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), host);
    auto realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    auto base = realhost & ~0xfffULL;
    // walk down to find the magic:
    for (auto i = 0; i < 0x10000; i++) {
        if (ReadKernel32(base) == MACH_HEADER_MAGIC) {
            return base;
        }
        base -= 0x1000;
    }
    return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv()
{
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    auto host = mach_host_self();
    auto hostport_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), host) : find_port_address(host, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), host);
    auto realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    // allocate a port
    auto port = TASK_NULL;
    auto err = KERN_FAILURE;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate port");
        return MACH_PORT_NULL;
    }

    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

    // locate the port
    auto port_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), port) : find_port_address(port, MACH_MSG_TYPE_COPY_SEND);

    // change the type of the port
    WriteKernel32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE | IKOT_HOST_PRIV);

    // change the space of the port
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());

    // set the kobject
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);

    fake_host_priv_port = port;

    return port;
}

kptr_t get_kernel_proc_struct_addr() {
    static auto kernproc = KPTR_NULL;
    if (!KERN_POINTER_VALID(kernproc)) {
        kernproc = ReadKernel64(ReadKernel64(GETOFFSET(kernel_task)) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        LOG("kernproc = " ADDR, kernproc);
        if (!KERN_POINTER_VALID(kernproc)) {
            LOG("failed to get kernproc!");
            return 0;
        }
    }
    return kernproc;
}

void iterate_proc_list(void (^handler)(kptr_t, pid_t, int *)) {
    assert(handler != NULL);
    auto proc = get_kernel_proc_struct_addr();
    if (!KERN_POINTER_VALID(proc)) {
        LOG("failed to get proc!");
        return;
    }
    auto iterate = true;
    while (proc && iterate) {
        auto pid = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        handler(proc, pid, &iterate);
        if (!iterate) {
            break;
        }
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST) + sizeof(void *));
    }
}

kptr_t get_proc_struct_for_pid(pid_t pid)
{
    __block auto proc = KPTR_NULL;
    iterate_proc_list(^(kptr_t found_proc, pid_t found_pid, int *iterate) {
        if (found_pid == pid) {
            proc = found_proc;
            *iterate = false;
        }
    });
    return proc;
}

kptr_t get_address_of_port(pid_t pid, mach_port_t port)
{
    
    static auto proc_struct_addr = KPTR_NULL;
    static auto task_addr = KPTR_NULL;
    static auto itk_space = KPTR_NULL;
    static auto is_table = KPTR_NULL;
    if (!KERN_POINTER_VALID(proc_struct_addr)) {
        proc_struct_addr = get_proc_struct_for_pid(pid);
        LOG("proc_struct_addr = " ADDR, proc_struct_addr);
        if (!KERN_POINTER_VALID(proc_struct_addr)) {
            LOG("failed to get proc_struct_addr!");
            return 0;
        }
    }
    if (!KERN_POINTER_VALID(task_addr)) {
        task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
        LOG("task_addr = " ADDR, task_addr);
        if (!KERN_POINTER_VALID(task_addr)) {
            LOG("failed to get task_addr!");
            return 0;
        }
    }
    if (!KERN_POINTER_VALID(itk_space)) {
        itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
        LOG("itk_space = " ADDR, itk_space);
        if (!KERN_POINTER_VALID(itk_space)) {
            LOG("failed to get itk_space!");
            return 0;
        }
    }
    if (!KERN_POINTER_VALID(is_table)) {
        is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
        LOG("is_table = " ADDR, is_table);
        if (!KERN_POINTER_VALID(is_table)) {
            LOG("failed to get is_table!");
            return 0;
        }
    }
    auto port_addr = ReadKernel64(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)));
    LOG("port_addr = " ADDR, port_addr);
    if (!KERN_POINTER_VALID(port_addr)) {
        LOG("failed to get port_addr!");
        return 0;
    }
    return port_addr;
}

kptr_t get_kernel_cred_addr()
{
    static auto kernel_proc_struct_addr = KPTR_NULL;
    static auto kernel_ucred_struct_addr = KPTR_NULL;
    if (!KERN_POINTER_VALID(kernel_proc_struct_addr)) {
        kernel_proc_struct_addr = get_proc_struct_for_pid(0);
        LOG("kernel_proc_struct_addr = " ADDR, kernel_proc_struct_addr);
        if (!KERN_POINTER_VALID(kernel_proc_struct_addr)) {
            LOG("failed to get kernel_proc_struct_addr!");
            return 0;
        }
    }
    if (!KERN_POINTER_VALID(kernel_ucred_struct_addr)) {
        kernel_ucred_struct_addr = ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        LOG("kernel_ucred_struct_addr = " ADDR, kernel_ucred_struct_addr);
        if (!KERN_POINTER_VALID(kernel_ucred_struct_addr)) {
            LOG("failed to get kernel_ucred_struct_addr!");
            return 0;
        }
    }
    return kernel_ucred_struct_addr;
}

kptr_t give_creds_to_process_at_addr(kptr_t proc, kptr_t cred_addr)
{
    auto orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    LOG("orig_creds = " ADDR, orig_creds);
    if (!KERN_POINTER_VALID(orig_creds)) {
        LOG("failed to get orig_creds!");
        return 0;
    }
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}

void set_platform_binary(kptr_t proc, bool set)
{
    auto task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    LOG("task_struct_addr = " ADDR, task_struct_addr);
    if (!KERN_POINTER_VALID(task_struct_addr)) {
        LOG("failed to get task_struct_addr!");
        return;
    }
    auto task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    if (set) {
        task_t_flags |= TF_PLATFORM;
    } else {
        task_t_flags &= ~(TF_PLATFORM);
    }
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}

// Thanks to @Siguza

kptr_t zm_fix_addr(kptr_t addr) {
    typedef struct {
        uint64_t prev;
        uint64_t next;
        uint64_t start;
        uint64_t end;
    } kmap_hdr_t;
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (!KERN_POINTER_VALID(zm_hdr.start)) {
        auto zone_map = ReadKernel64(GETOFFSET(zone_map_ref));
        LOG("zone_map: " ADDR, zone_map);
        // hdr is at offset 0x10, mutexes at start
        auto r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        LOG("zm_range: " ADDR " - " ADDR " (read 0x%zx, exp 0x%zx)", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        if (r != sizeof(zm_hdr) || !KERN_POINTER_VALID(zm_hdr.start) || !KERN_POINTER_VALID(zm_hdr.end)) {
            LOG("kread of zone_map failed!");
            return 0;
        }
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            LOG("zone_map is too big, sorry.");
            return 0;
        }
    }
    auto zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}

bool verify_tfp0() {
    auto test_size = sizeof(kptr_t);
    auto test_kptr = kmem_alloc(test_size);
    if (!KERN_POINTER_VALID(test_kptr)) {
        LOG("failed to allocate kernel memory!");
        return false;
    }
    auto test_write_data = 0x4141414141414141;
    if (!wkbuffer(test_kptr, (void *)&test_write_data, test_size)) {
        LOG("failed to write to kernel memory!");
        return false;
    }
    auto test_read_data = KPTR_NULL;
    if (!rkbuffer(test_kptr, (void *)&test_read_data, test_size)) {
        LOG("failed to read kernel memory!");
        return false;
    }
    if (test_write_data != test_read_data) {
        LOG("failed to verify kernel memory read data!");
        return false;
    }
    if (!kmem_free(test_kptr, test_size)) {
        LOG("failed to deallocate kernel memory!");
        return false;
    }
    return true;
}

int (*pmap_load_trust_cache)(kptr_t kernel_trust, size_t length) = NULL;
int _pmap_load_trust_cache(kptr_t kernel_trust, size_t length) {
    return (int)kexecute(GETOFFSET(pmap_load_trust_cache), kernel_trust, length, 0, 0, 0, 0, 0);
}

void set_host_type(host_t host, uint32_t type) {
    auto hostport_addr = get_address_of_port(getpid(), host);
    auto old = ReadKernel32(hostport_addr);
    LOG("old host type: 0x%08x", old);
    if ((old & type) != type) {
        WriteKernel32(hostport_addr, type);
        auto new = ReadKernel32(hostport_addr);
        LOG("new host type: 0x%08x", new);
    }
}

void export_tfp0(host_t host) {
    set_host_type(host, IO_ACTIVE | IKOT_HOST_PRIV);
}

void unexport_tfp0(host_t host) {
    set_host_type(host, IO_ACTIVE | IKOT_HOST);
}

void set_csflags(kptr_t proc, uint32_t flags, bool value) {
    auto csflags = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}

void set_cs_platform_binary(kptr_t proc, bool value) {
    set_csflags(proc, CS_PLATFORM_BINARY, value);
}

bool execute_with_credentials(kptr_t proc, kptr_t credentials, void (^function)(void)) {
    assert(function != NULL);
    auto saved_credentials = give_creds_to_process_at_addr(proc, credentials);
    function();
    return (give_creds_to_process_at_addr(proc, saved_credentials) == saved_credentials);
}

uint32_t get_proc_memstat_state(kptr_t proc) {
    return ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE));
}

void set_proc_memstat_state(kptr_t proc, uint32_t memstat_state) {
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE), memstat_state);
}

void set_proc_memstat_internal(kptr_t proc, bool set) {
    auto memstat_state = get_proc_memstat_state(proc);
    if (set) {
        memstat_state |= P_MEMSTAT_INTERNAL;
    } else {
        memstat_state &= ~P_MEMSTAT_INTERNAL;
    }
    set_proc_memstat_state(proc, memstat_state);
}

bool get_proc_memstat_internal(kptr_t proc) {
    return (get_proc_memstat_state(proc) & P_MEMSTAT_INTERNAL);
}

size_t kstrlen(kptr_t ptr) {
    auto kstrlen = (size_t)kexecute(GETOFFSET(strlen), ptr, 0, 0, 0, 0, 0, 0);
    return kstrlen;
}

kptr_t kstralloc(const char *str) {
    auto str_kptr_size = strlen(str) + 1;
    auto str_kptr = kmem_alloc(str_kptr_size);
    if (KERN_POINTER_VALID(str_kptr)) {
        kwrite(str_kptr, str, str_kptr_size);
    }
    return str_kptr;
}

void kstrfree(kptr_t ptr) {
    if (KERN_POINTER_VALID(ptr)) {
        auto size = kstrlen(ptr);
        kmem_free(ptr, size);
    }
}

kptr_t sstrdup(const char *str) {
    auto sstrdup = KPTR_NULL;
    auto kstr = kstralloc(str);
    if (KERN_POINTER_VALID(kstr)) {
        sstrdup = kexecute(GETOFFSET(sstrdup), kstr, 0, 0, 0, 0, 0, 0);
        sstrdup = zm_fix_addr(sstrdup);
        kstrfree(kstr);
    }
    return sstrdup;
}

kptr_t smalloc(size_t size) {
    auto smalloc = kexecute(GETOFFSET(smalloc), (kptr_t)size, 0, 0, 0, 0, 0, 0);
    smalloc = zm_fix_addr(smalloc);
    return smalloc;
}

void sfree(kptr_t ptr) {
    kexecute(GETOFFSET(sfree), ptr, 0, 0, 0, 0, 0, 0);
}

int extension_create_file(kptr_t saveto, kptr_t sb, const char *path, size_t path_len, uint32_t subtype) {
    auto extension_create_file = -1;
    auto kstr = kstralloc(path);
    if (KERN_POINTER_VALID(kstr)) {
        extension_create_file = (int)kexecute(GETOFFSET(extension_create_file), saveto, sb, kstr, (kptr_t)path_len, (kptr_t)subtype, 0, 0);
        kstrfree(kstr);
    }
    return extension_create_file;
}

int extension_create_mach(kptr_t saveto, kptr_t sb, const char *name, uint32_t subtype) {
    auto extension_create_mach = -1;
    auto kstr = kstralloc(name);
    if (KERN_POINTER_VALID(kstr)) {
        extension_create_mach = (int)kexecute(GETOFFSET(extension_create_mach), saveto, sb, kstr, (kptr_t)subtype, 0, 0, 0);
        kstrfree(kstr);
    }
    return extension_create_mach;
}

int extension_add(kptr_t ext, kptr_t sb, const char *desc) {
    auto extension_add = -1;
    auto kstr = kstralloc(desc);
    if (KERN_POINTER_VALID(kstr)) {
        extension_add = (int)kexecute(GETOFFSET(extension_add), ext, sb, kstr, 0, 0, 0, 0);
        kstrfree(kstr);
    }
    return extension_add;
}

void extension_release(kptr_t ext) {
    kexecute(GETOFFSET(extension_release), ext, 0, 0, 0, 0, 0, 0);
}

void extension_destroy(kptr_t ext) {
    kexecute(GETOFFSET(extension_destroy), ext, 0, 0, 0, 0, 0, 0);
}

bool set_file_extension(kptr_t sandbox, const char *exc_key, const char *path) {
    auto set_file_extension = false;
    if (KERN_POINTER_VALID(sandbox)) {
        auto ext = smalloc(SIZEOF_STRUCT_EXTENSION);
        if (KERN_POINTER_VALID(ext)) {
            auto ret_extension_create_file = extension_create_file(ext, sandbox, path, strlen(path) + 1, 0);
            if (ret_extension_create_file == 0) {
                auto ret_extension_add = extension_add(ext, sandbox, exc_key);
                if (ret_extension_add == 0) {
                    set_file_extension = true;
                }
            }
            extension_release(ext);
        }
    } else {
        set_file_extension = true;
    }
    return set_file_extension;
}

bool set_mach_extension(kptr_t sandbox, const char *exc_key, const char *name) {
    auto set_mach_extension = false;
    if (KERN_POINTER_VALID(sandbox)) {
        auto ext = smalloc(SIZEOF_STRUCT_EXTENSION);
        if (KERN_POINTER_VALID(ext)) {
            auto ret_extension_create_mach = extension_create_mach(ext, sandbox, name, 0);
            if (ret_extension_create_mach == 0) {
                auto ret_extension_add = extension_add(ext, sandbox, exc_key);
                if (ret_extension_add == 0) {
                    set_mach_extension = true;
                }
            }
            extension_release(ext);
        }
    } else {
        set_mach_extension = true;
    }
    return set_mach_extension;
}

kptr_t proc_find(pid_t pid) {
    auto proc_find = kexecute(GETOFFSET(proc_find), (kptr_t)pid, 0, 0, 0, 0, 0, 0);
    if (proc_find != 0) {
        proc_find = zm_fix_addr(proc_find);
    }
    return proc_find;
}

void proc_rele(kptr_t proc) {
    kexecute(GETOFFSET(proc_rele), proc, 0, 0, 0, 0, 0, 0);
}

void proc_lock(kptr_t proc) {
    auto function = GETOFFSET(proc_lock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void proc_unlock(kptr_t proc) {
    auto function = GETOFFSET(proc_unlock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void proc_ucred_lock(kptr_t proc) {
    auto function = GETOFFSET(proc_ucred_lock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void proc_ucred_unlock(kptr_t proc) {
    auto function = GETOFFSET(proc_ucred_unlock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void vnode_lock(kptr_t vp) {
    auto function = GETOFFSET(vnode_lock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, vp, 0, 0, 0, 0, 0, 0);
    }
}

void vnode_unlock(kptr_t vp) {
    auto function = GETOFFSET(vnode_unlock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, vp, 0, 0, 0, 0, 0, 0);
    }
}

void mount_lock(kptr_t mp) {
    auto function = GETOFFSET(mount_lock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, mp, 0, 0, 0, 0, 0, 0);
    }
}

void mount_unlock(kptr_t mp) {
    auto function = GETOFFSET(mount_unlock);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, mp, 0, 0, 0, 0, 0, 0);
    }
}

void task_set_platform_binary(kptr_t task, boolean_t is_platform) {
    auto function = GETOFFSET(task_set_platform_binary);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, task, (kptr_t)is_platform, 0, 0, 0, 0, 0);
    }
}

int chgproccnt(uid_t uid, int diff) {
    auto chgproccnt = 0;
    auto function = GETOFFSET(chgproccnt);
    if (KERN_POINTER_VALID(function)) {
        chgproccnt = (int)kexecute(function, (kptr_t)uid, (kptr_t)diff, 0, 0, 0, 0, 0);
    }
    return chgproccnt;
}

void kauth_cred_ref(kptr_t cred) {
    auto function = GETOFFSET(kauth_cred_ref);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, cred, 0, 0, 0, 0, 0, 0);
    }
}

void kauth_cred_unref(kptr_t cred) {
    auto function = GETOFFSET(kauth_cred_unref);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, cred, 0, 0, 0, 0, 0, 0);
    }
}

kptr_t vfs_context_current() {
    auto vfs_context_current = kexecute(GETOFFSET(vfs_context_current), 1, 0, 0, 0, 0, 0, 0);
    vfs_context_current = zm_fix_addr(vfs_context_current);
    return vfs_context_current;
}

int vnode_lookup(const char *path, int flags, kptr_t *vpp, kptr_t ctx) {
    auto vnode_lookup = -1;
    auto kstr = kstralloc(path);
    if (KERN_POINTER_VALID(kstr)) {
        auto vpp_kptr_size = sizeof(kptr_t);
        auto vpp_kptr = kmem_alloc(vpp_kptr_size);
        if (KERN_POINTER_VALID(vpp_kptr)) {
            vnode_lookup = (int)kexecute(GETOFFSET(vnode_lookup), kstr, (kptr_t)flags, vpp_kptr, ctx, 0, 0, 0);
            if (vnode_lookup == 0) {
                if (vpp != NULL) {
                    *vpp = ReadKernel64(vpp_kptr);
                }
            }
            kmem_free(vpp_kptr, vpp_kptr_size);
        }
        kstrfree(kstr);
    }
    return vnode_lookup;
}

int vnode_put(kptr_t vp) {
    auto vnode_put = (int)kexecute(GETOFFSET(vnode_put), vp, 0, 0, 0, 0, 0, 0);
    return vnode_put;
}

bool OSDictionary_SetItem(kptr_t OSDictionary, const char *key, kptr_t val) {
    auto OSDictionary_SetItem = false;
    auto function = OSObjectFunc(OSDictionary, off_OSDictionary_SetObjectWithCharP);
    if (KERN_POINTER_VALID(function)) {
        auto kstr = kstralloc(key);
        if (KERN_POINTER_VALID(kstr)) {
            OSDictionary_SetItem = (bool)kexecute(function, OSDictionary, kstr, val, 0, 0, 0, 0);
            kstrfree(kstr);
        }
    }
    return OSDictionary_SetItem;
}

kptr_t OSDictionary_GetItem(kptr_t OSDictionary, const char *key) {
    auto OSDictionary_GetItem = KPTR_NULL;
    auto function = OSObjectFunc(OSDictionary, off_OSDictionary_GetObjectWithCharP);
    if (KERN_POINTER_VALID(function)) {
        auto kstr = kstralloc(key);
        if (KERN_POINTER_VALID(kstr)) {
            OSDictionary_GetItem = kexecute(function, OSDictionary, kstr, 0, 0, 0, 0, 0);
            if (OSDictionary_GetItem != KPTR_NULL && (OSDictionary_GetItem >> 32) == 0) {
                OSDictionary_GetItem = zm_fix_addr(OSDictionary_GetItem);
            }
            kstrfree(kstr);
        }
    }
    return OSDictionary_GetItem;
}

bool OSDictionary_Merge(kptr_t OSDictionary, kptr_t OSDictionary2) {
    auto OSDictionary_Merge = false;
    auto function = OSObjectFunc(OSDictionary, off_OSDictionary_Merge);
    if (KERN_POINTER_VALID(function)) {
        OSDictionary_Merge = (bool)kexecute(function, OSDictionary, OSDictionary2, 0, 0, 0, 0, 0);
    }
    return OSDictionary_Merge;
}

uint32_t OSDictionary_ItemCount(kptr_t OSDictionary) {
    auto OSDictionary_ItemCount = (uint32_t)0;
    if (KERN_POINTER_VALID(OSDictionary)) {
        OSDictionary_ItemCount = ReadKernel32(OSDictionary + 20);
    }
    return OSDictionary_ItemCount;
}

kptr_t OSDictionary_ItemBuffer(kptr_t OSDictionary) {
    auto OSDictionary_ItemBuffer = KPTR_NULL;
    if (KERN_POINTER_VALID(OSDictionary)) {
        OSDictionary_ItemBuffer = ReadKernel64(OSDictionary + 32);
    }
    return OSDictionary_ItemBuffer;
}

kptr_t OSDictionary_ItemKey(kptr_t buffer, uint32_t idx) {
    auto OSDictionary_ItemKey = KPTR_NULL;
    if (KERN_POINTER_VALID(buffer)) {
        OSDictionary_ItemKey = ReadKernel64(buffer + 16 * idx);
    }
    return OSDictionary_ItemKey;
}

kptr_t OSDictionary_ItemValue(kptr_t buffer, uint32_t idx) {
    auto OSDictionary_ItemValue = KPTR_NULL;
    if (KERN_POINTER_VALID(buffer)) {
        OSDictionary_ItemValue = ReadKernel64(buffer + 16 * idx + 8);
    }
    return OSDictionary_ItemValue;
}

bool OSArray_Merge(kptr_t OSArray, kptr_t OSArray2) {
    auto OSArray_Merge = false;
    auto function = OSObjectFunc(OSArray, off_OSArray_Merge);
    if (KERN_POINTER_VALID(function)) {
        OSArray_Merge = (bool)kexecute(function, OSArray, OSArray2, 0, 0, 0, 0, 0);
    }
    return OSArray_Merge;
}

kptr_t OSArray_GetObject(kptr_t OSArray, uint32_t idx) {
    auto OSArray_GetObject = KPTR_NULL;
    auto function = OSObjectFunc(OSArray, off_OSArray_GetObject);
    if (KERN_POINTER_VALID(function)) {
        OSArray_GetObject = kexecute(OSArray, idx, 0, 0, 0, 0, 0, 0);
        if (OSArray_GetObject != KPTR_NULL) {
            OSArray_GetObject = zm_fix_addr(OSArray_GetObject);
        }
    }
    return OSArray_GetObject;
}

void OSArray_RemoveObject(kptr_t OSArray, uint32_t idx) {
    auto function = OSObjectFunc(OSArray, off_OSArray_RemoveObject);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, OSArray, idx, 0, 0, 0, 0, 0);
    }
}

uint32_t OSArray_ItemCount(kptr_t OSArray) {
    auto OSArray_ItemCount = (uint32_t)0;
    if (KERN_POINTER_VALID(OSArray)) {
        OSArray_ItemCount = ReadKernel32(OSArray + 0x14);
    }
    return OSArray_ItemCount;
}

kptr_t OSArray_ItemBuffer(kptr_t OSArray) {
    auto OSArray_ItemBuffer = KPTR_NULL;
    if (KERN_POINTER_VALID(OSArray)) {
        OSArray_ItemBuffer = ReadKernel64(OSArray + 32);
    }
    return OSArray_ItemBuffer;
}

kptr_t OSObjectFunc(kptr_t OSObject, uint32_t off) {
    auto OSObjectFunc = KPTR_NULL;
    auto vtable = ReadKernel64(OSObject);
    vtable = kernel_xpacd(vtable);
    if (KERN_POINTER_VALID(vtable)) {
        OSObjectFunc = ReadKernel64(vtable + off);
        OSObjectFunc = kernel_xpaci(OSObjectFunc);
    }
    return OSObjectFunc;
}

void OSObject_Release(kptr_t OSObject) {
    auto function = OSObjectFunc(OSObject, off_OSObject_Release);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

void OSObject_Retain(kptr_t OSObject) {
    auto function = OSObjectFunc(OSObject, off_OSObject_Retain);
    if (KERN_POINTER_VALID(function)) {
        kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

uint32_t OSObject_GetRetainCount(kptr_t OSObject) {
    auto OSObject_GetRetainCount = (uint32_t)0;
    auto function = OSObjectFunc(OSObject, off_OSObject_GetRetainCount);
    if (KERN_POINTER_VALID(function)) {
        OSObject_GetRetainCount = (uint32_t)kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
    return OSObject_GetRetainCount;
}

uint32_t OSString_GetLength(kptr_t OSString) {
    auto OSString_GetLength = (uint32_t)0;
    auto function = OSObjectFunc(OSString, off_OSString_GetLength);
    if (KERN_POINTER_VALID(function)) {
        OSString_GetLength = (uint32_t)kexecute(function, OSString, 0, 0, 0, 0, 0, 0);
    }
    return OSString_GetLength;
}

kptr_t OSString_CStringPtr(kptr_t OSString) {
    auto OSString_CStringPtr = KPTR_NULL;
    if (KERN_POINTER_VALID(OSString)) {
        OSString_CStringPtr = ReadKernel64(OSString + 0x10);
    }
    return OSString_CStringPtr;
}

char *OSString_CopyString(kptr_t OSString) {
    auto OSString_CopyString = (char *)NULL;
    auto length = OSString_GetLength(OSString);
    if (length != 0) {
        auto str = (char *)malloc(length + 1);
        if (str != NULL) {
            str[length] = 0;
            auto CStringPtr = OSString_CStringPtr(OSString);
            if (KERN_POINTER_VALID(CStringPtr)) {
                if (kread(CStringPtr, str, length) == length) {
                    OSString_CopyString = strdup(str);
                }
            }
            SafeFreeNULL(str);
        }
    }
    return OSString_CopyString;
}

kptr_t OSUnserializeXML(const char *buffer) {
    auto OSUnserializeXML = KPTR_NULL;
    auto kstr = kstralloc(buffer);
    if (KERN_POINTER_VALID(kstr)) {
        auto error_kptr = KPTR_NULL;
        OSUnserializeXML = kexecute(GETOFFSET(osunserializexml), kstr, error_kptr, 0, 0, 0, 0, 0);
        if (OSUnserializeXML != KPTR_NULL) {
            OSUnserializeXML = zm_fix_addr(OSUnserializeXML);
        }
        kstrfree(kstr);
    }
    return OSUnserializeXML;
}

kptr_t get_exception_osarray(const char **exceptions) {
    auto exception_osarray = KPTR_NULL;
    auto xmlsize = (size_t)0x1000;
    auto len = SIZE_NULL;
    auto written = SIZE_NULL;
    auto ents = (char *)malloc(xmlsize);
    if (!ents) {
        return 0;
    }
    auto xmlused = sprintf(ents, "<array>");
    for (auto exception = exceptions; *exception; exception++) {
        len = strlen(*exception);
        len += strlen("<string></string>");
        while (xmlused + len >= xmlsize) {
            xmlsize += 0x1000;
            ents = reallocf(ents, xmlsize);
            if (!ents) {
                return 0;
            }
        }
        written = sprintf(ents + xmlused, "<string>%s/</string>", *exception);
        if (written < 0) {
            SafeFreeNULL(ents);
            return 0;
        }
        xmlused += written;
    }
    len = strlen("</array>");
    if (xmlused + len >= xmlsize) {
        xmlsize += len;
        ents = reallocf(ents, xmlsize);
        if (!ents) {
            return 0;
        }
    }
    written = sprintf(ents + xmlused, "</array>");
    
    exception_osarray = OSUnserializeXML(ents);
    SafeFreeNULL(ents);
    return exception_osarray;
}

char **copy_amfi_entitlements(kptr_t present) {
    auto itemCount = OSArray_ItemCount(present);
    auto itemBuffer = OSArray_ItemBuffer(present);
    auto bufferSize = 0x1000;
    auto bufferUsed = 0;
    auto arraySize = (itemCount + 1) * sizeof(char *);
    auto entitlements = (char **)malloc(arraySize + bufferSize);
    if (!entitlements) {
        return NULL;
    }
    entitlements[itemCount] = NULL;
    
    for (auto i = 0; i < itemCount; i++) {
        auto item = ReadKernel64(itemBuffer + (i * sizeof(void *)));
        auto entitlementString = OSString_CopyString(item);
        if (!entitlementString) {
            SafeFreeNULL(entitlements);
            return NULL;
        }
        auto len = strlen(entitlementString) + 1;
        while (bufferUsed + len > bufferSize) {
            bufferSize += 0x1000;
            entitlements = realloc(entitlements, arraySize + bufferSize);
            if (!entitlements) {
                SafeFreeNULL(entitlementString);
                return NULL;
            }
        }
        entitlements[i] = (char*)entitlements + arraySize + bufferUsed;
        strcpy(entitlements[i], entitlementString);
        bufferUsed += len;
        SafeFreeNULL(entitlementString);
    }
    return entitlements;
}

kptr_t getOSBool(bool value) {
    auto OSBool = KPTR_NULL;
    if (value) {
        OSBool = ReadKernel64(GETOFFSET(OSBoolean_True));
    } else {
        OSBool = ReadKernel64(GETOFFSET(OSBoolean_True)) + sizeof(void *);
    }
    return OSBool;
}

bool entitleProcess(kptr_t amfi_entitlements, const char *key, kptr_t val) {
    auto entitleProcess = false;
    if (KERN_POINTER_VALID(amfi_entitlements)) {
        if (OSDictionary_GetItem(amfi_entitlements, key) != val) {
            entitleProcess = OSDictionary_SetItem(amfi_entitlements, key, val);
        }
    }
    return entitleProcess;
}

bool exceptionalizeProcess(kptr_t sandbox, kptr_t amfi_entitlements, const char **exceptions) {
    bool exceptionalizeProcess = true;
    if (KERN_POINTER_VALID(sandbox)) {
        for (auto exception = exceptions; *exception; exception++) {
            if (!set_file_extension(sandbox, FILE_EXC_KEY, *exception)) {
                exceptionalizeProcess = false;
            }
        }
        if (KERN_POINTER_VALID(amfi_entitlements)) {
            auto presentExceptionOSArray = OSDictionary_GetItem(amfi_entitlements, FILE_EXC_KEY);
            if (KERN_POINTER_VALID(presentExceptionOSArray)) {
                auto currentExceptions = copy_amfi_entitlements(presentExceptionOSArray);
                if (currentExceptions != NULL) {
                    for (auto exception = exceptions; *exception; exception++) {
                        auto foundException = false;
                        for (auto entitlementString = currentExceptions; *entitlementString && !foundException; entitlementString++) {
                            auto ent = strdup(*entitlementString);
                            if (ent != NULL) {
                                auto lastchar = strlen(ent) - 1;
                                if (ent[lastchar] == '/') ent[lastchar] = '\0';
                                if (strcasecmp(ent, *exception) == 0) {
                                    foundException = true;
                                }
                                SafeFreeNULL(ent);
                            }
                        }
                        if (!foundException) {
                            auto exception_array = (const char **)malloc(((1 + 1) * sizeof(char *)) + MAXPATHLEN);
                            if (exception_array != NULL) {
                                exception_array[0] = *exception;
                                exception_array[1] = NULL;
                                auto exceptionOSArray = get_exception_osarray(exception_array);
                                if (KERN_POINTER_VALID(exceptionOSArray)) {
                                    if (!OSArray_Merge(presentExceptionOSArray, exceptionOSArray)) {
                                        exceptionalizeProcess = false;
                                    }
                                    OSObject_Release(exceptionOSArray);
                                }
                                SafeFreeNULL(exception_array);
                            }
                        }
                    }
                    SafeFreeNULL(currentExceptions);
                }
            } else {
                auto exceptionOSArray = get_exception_osarray(exceptions);
                if (KERN_POINTER_VALID(exceptionOSArray)) {
                    if (!OSDictionary_SetItem(amfi_entitlements, FILE_EXC_KEY, exceptionOSArray)) {
                        exceptionalizeProcess = false;
                    }
                    OSObject_Release(exceptionOSArray);
                }
            }
        }
    }
    return exceptionalizeProcess;
}

bool unrestrictProcess(pid_t pid) {
    bool unrestrictProcess = true;
    LOG("%s(%d): Unrestricting", __FUNCTION__, pid);
    auto proc = proc_find(pid);
    if (KERN_POINTER_VALID(proc)) {
        LOG("%s(%d): Found proc: " ADDR, __FUNCTION__, pid, proc);
        auto proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        LOG("%s(%d): Found proc_ucred: " ADDR, __FUNCTION__, pid, proc_ucred);
        if (KERN_POINTER_VALID(proc_ucred)) {
            auto path = get_path_for_pid(pid);
            if (path != NULL) {
                LOG("%s(%d): Found path: %s", __FUNCTION__, pid, path);
                struct stat statbuf;
                if (lstat(path, &statbuf) == 0) {
                    LOG("%s(%d): Got stat for path", __FUNCTION__, pid);
                    if ((statbuf.st_mode & S_ISUID)) {
                        LOG("%s(%d): Enabling setuid", __FUNCTION__, pid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_SVUID), statbuf.st_uid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_SVUID), statbuf.st_uid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), statbuf.st_uid);
                    }
                    if ((statbuf.st_mode & S_ISGID)) {
                        LOG("%s(%d): Enabling setgid", __FUNCTION__, pid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_SVGID), statbuf.st_gid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_SVGID), statbuf.st_gid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_GROUPS), statbuf.st_gid);
                    }
                } else {
                    LOG("%s(%d): Unable to get stat for path", __FUNCTION__, pid);
                    unrestrictProcess = false;
                }
                SafeFreeNULL(path);
            } else {
                LOG("%s(%d): Unable to find path", __FUNCTION__, pid);
                unrestrictProcess = false;
            }
            auto cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
            if (KERN_POINTER_VALID(cr_label)) {
                LOG("%s(%d): Found cr_label: " ADDR, __FUNCTION__, pid, cr_label);
                auto amfi_entitlements = get_amfi_entitlements(cr_label);
                auto sandbox = get_sandbox(cr_label);
                LOG("%s(%d): Entitling process with: %s", __FUNCTION__, pid, "com.apple.private.skip-library-validation");
                entitleProcess(amfi_entitlements, "com.apple.private.skip-library-validation", OSBoolTrue);
                if (OPT(GET_TASK_ALLOW)) {
                    LOG("%s(%d): Entitling process with: %s", __FUNCTION__, pid, "get-task-allow");
                    entitleProcess(amfi_entitlements, "get-task-allow", OSBoolTrue);
                }
                LOG("%s(%d): Exceptionalizing process with: %s", __FUNCTION__, pid, "abs_path_exceptions");
                if (!exceptionalizeProcess(sandbox, amfi_entitlements, abs_path_exceptions)) {
                    LOG("%s(%d): Unable to exceptionalize process", __FUNCTION__, pid);
                    unrestrictProcess = false;
                }
                if (KERN_POINTER_VALID(amfi_entitlements)) {
                    if (OSDictionary_GetItem(amfi_entitlements, "platform-application") == OSBoolTrue) {
                        LOG("%s(%d): Setting TF_PLATFORM", __FUNCTION__, pid);
                        set_platform_binary(proc, true);
                    }
                }
            } else {
                LOG("%s(%d): Unable to find cr_label", __FUNCTION__, pid);
                unrestrictProcess = false;
            }
        } else {
            LOG("%s(%d): Unable to find proc_ucred", __FUNCTION__, pid);
            unrestrictProcess = false;
        }
        auto cs_flags = 0;
        if (csops(pid, CS_OPS_STATUS, (void *)&cs_flags, sizeof(cs_flags)) == 0) {
            LOG("%s(%d): Found cs_flags: 0x%x", __FUNCTION__, pid, cs_flags);
            if (!(cs_flags & CS_PLATFORM_BINARY)) {
                LOG("%s(%d): Setting CS_PLATFORM_BINARY", __FUNCTION__, pid);
                set_csflags(proc, CS_PLATFORM_BINARY, true);
            }
            if ((cs_flags & CS_REQUIRE_LV)) {
                LOG("%s(%d): Unsetting CS_REQUIRE_LV", __FUNCTION__, pid);
                set_csflags(proc, CS_REQUIRE_LV, false);
            }
            if ((cs_flags & CS_CHECK_EXPIRATION)) {
                LOG("%s(%d): Unsetting CS_CHECK_EXPIRATION", __FUNCTION__, pid);
                set_csflags(proc, CS_CHECK_EXPIRATION, false);
            }
            if (!(cs_flags & CS_DYLD_PLATFORM)) {
                LOG("%s(%d): Setting CS_DYLD_PLATFORM", __FUNCTION__, pid);
                set_csflags(proc, CS_DYLD_PLATFORM, true);
            }
            if (OPT(GET_TASK_ALLOW)) {
                if (!(cs_flags & CS_GET_TASK_ALLOW)) {
                    LOG("%s(%d): Setting CS_GET_TASK_ALLOW", __FUNCTION__, pid);
                    set_csflags(proc, CS_GET_TASK_ALLOW, true);
                }
                if (!(cs_flags & CS_INSTALLER)) {
                    LOG("%s(%d): Setting CS_INSTALLER", __FUNCTION__, pid);
                    set_csflags(proc, CS_INSTALLER, true);
                }
                if ((cs_flags & CS_RESTRICT)) {
                    LOG("%s(%d): Unsetting CS_RESTRICT", __FUNCTION__, pid);
                    set_csflags(proc, CS_RESTRICT, false);
                }
            }
            if (OPT(CS_DEBUGGED)) {
                if (!(cs_flags & CS_DEBUGGED)) {
                    LOG("%s(%d): Setting CS_DEBUGGED", __FUNCTION__, pid);
                    set_csflags(proc, CS_DEBUGGED, true);
                }
                if ((cs_flags & CS_HARD)) {
                    LOG("%s(%d): Unsetting CS_HARD", __FUNCTION__, pid);
                    set_csflags(proc, CS_HARD, false);
                }
                if ((cs_flags & CS_KILL)) {
                    LOG("%s(%d): Unsetting CS_KILL", __FUNCTION__, pid);
                    set_csflags(proc, CS_KILL, false);
                }
            }
        } else {
            LOG("%s(%d): Unable to find cs_flags", __FUNCTION__, pid);
            unrestrictProcess = false;
        }
        LOG("%s(%d): Releasing proc", __FUNCTION__, pid);
        proc_rele(proc);
    } else {
        LOG("%s(%d): Unable to find proc", __FUNCTION__, pid);
        unrestrictProcess = false;
    }
    if (unrestrictProcess) {
        LOG("%s(%d): Unrestricted process", __FUNCTION__, pid);
    } else {
        LOG("%s(%d): Unable to unrestrict process", __FUNCTION__, pid);
    }
    return unrestrictProcess;
}

bool unrestrictProcessWithTaskPort(task_t task_port) {
    bool unrestrictProcessWithTaskPort = false;
    auto pid = 0;
    if (pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS) {
        unrestrictProcessWithTaskPort = unrestrictProcess(pid);
    }
    return unrestrictProcessWithTaskPort;
}

bool revalidateProcess(pid_t pid) {
    bool revalidateProcess = true;
    LOG("%s(%d): Revalidating", __FUNCTION__, pid);
    auto cs_flags = 0;
    if (csops(pid, CS_OPS_STATUS, (void *)&cs_flags, sizeof(cs_flags)) == 0) {
        if (!(cs_flags & CS_VALID)) {
            auto proc = proc_find(pid);
            if (KERN_POINTER_VALID(proc)) {
                LOG("%s(%d): Found proc: " ADDR, __FUNCTION__, pid, proc);
                LOG("%s(%d): Setting CS_VALID", __FUNCTION__, pid);
                set_csflags(proc, CS_VALID, true);
                LOG("%s(%d): Releasing proc", __FUNCTION__, pid);
                proc_rele(proc);
            } else {
                LOG("%s(%d): Unable to find proc", __FUNCTION__, pid);
                revalidateProcess = false;
            }
        }
    }
    if (revalidateProcess) {
        LOG("%s(%d): Revalidated process", __FUNCTION__, pid);
    } else {
        LOG("%s(%d): Unable to revalidate process", __FUNCTION__, pid);
    }
    return revalidateProcess;
}

bool revalidateProcessWithTaskPort(task_t task_port) {
    auto revalidateProcessWithTaskPort = false;
    auto pid = 0;
    if (pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS) {
        revalidateProcessWithTaskPort = revalidateProcess(pid);
    }
    return revalidateProcessWithTaskPort;
}

kptr_t get_amfi_entitlements(kptr_t cr_label) {
    auto amfi_entitlements = KPTR_NULL;
    amfi_entitlements = ReadKernel64(cr_label + 0x8);
    return amfi_entitlements;
}

kptr_t get_sandbox(kptr_t cr_label) {
    auto sandbox = KPTR_NULL;
    sandbox = ReadKernel64(cr_label + 0x8 + 0x8);
    return sandbox;
}

bool entitleProcessWithPid(pid_t pid, const char *key, kptr_t val) {
    auto entitleProcessWithPid = true;
    auto proc = proc_find(pid);
    if (KERN_POINTER_VALID(proc)) {
        LOG("%s: Found proc: " ADDR, __FUNCTION__, proc);
        auto proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        if (KERN_POINTER_VALID(proc_ucred)) {
            LOG("%s: Found proc_ucred: " ADDR, __FUNCTION__, proc_ucred);
            auto cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
            if (KERN_POINTER_VALID(cr_label)) {
                LOG("%s: Found cr_label: " ADDR, __FUNCTION__, cr_label);
                auto amfi_entitlements = get_amfi_entitlements(cr_label);
                if (KERN_POINTER_VALID(amfi_entitlements)) {
                    LOG("%s: Found amfi_entitlements: " ADDR, __FUNCTION__, amfi_entitlements);
                    entitleProcessWithPid = entitleProcess(amfi_entitlements, key, val);
                } else {
                    LOG("%s: Unable to find amfi_entitlements", __FUNCTION__);
                    entitleProcessWithPid = false;
                }
            } else {
                LOG("%s: Unable to find cr_label", __FUNCTION__);
                entitleProcessWithPid = false;
            }
        } else {
            LOG("%s: Unable to find proc_ucred", __FUNCTION__);
            entitleProcessWithPid = false;
        }
        LOG("%s: Releasing proc: " ADDR, __FUNCTION__, proc);
        proc_rele(proc);
    } else {
        LOG("%s: Unable to find proc", __FUNCTION__);
        entitleProcessWithPid = false;
    }
    return entitleProcessWithPid;
}

bool removeMemoryLimit() {
    auto removeMemoryLimit = false;
    if (entitleProcessWithPid(getpid(), "com.apple.private.memorystatus", OSBoolTrue)) {
        if (memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 0, NULL, 0) == 0) {
            removeMemoryLimit = true;
        }
    }
    return removeMemoryLimit;
}
