//
//  JailbreakViewController.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#include <sys/snapshot.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <spawn.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <common.h>
#include <iokit.h>
#include <NSTask.h>
#include <MobileGestalt.h>
#include <netdb.h>
#include <reboot.h>
#import <snappy.h>
#import <inject.h>
#include <sched.h>
#import <patchfinder64.h>
#import <offsetcache.h>
#import <kerneldec.h>
#import "JailbreakViewController.h"
#include "KernelStructureOffsets.h"
#include "empty_list_sploit.h"
#include "KernelMemory.h"
#include "KernelExecution.h"
#include "KernelUtilities.h"
#include "remote_memory.h"
#include "remote_call.h"
#include "unlocknvram.h"
#include "SettingsTableViewController.h"
#include "multi_path_sploit.h"
#include "async_wake.h"
#include "utils.h"
#include "ArchiveFile.h"
#include "CreditsTableViewController.h"
#include "FakeApt.h"
#include "voucher_swap.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "find_port.h"
#include "machswap_offsets.h"
#include "machswap_pwn.h"
#include "machswap2_pwn.h"
#include "prefs.h"

@interface JailbreakViewController ()

@end

@implementation JailbreakViewController
static JailbreakViewController *sharedController = nil;
static NSMutableString *output = nil;

#define STATUS(msg, btnenbld, tbenbld) do { \
        LOG("STATUS: %@", msg); \
        dispatch_async(dispatch_get_main_queue(), ^{ \
            [UIView performWithoutAnimation:^{ \
                [[[JailbreakViewController sharedController] goButton] setEnabled:btnenbld]; \
                [[[[JailbreakViewController sharedController] tabBarController] tabBar] setUserInteractionEnabled:tbenbld]; \
                [[[JailbreakViewController sharedController] goButton] setTitle:msg forState: btnenbld ? UIControlStateNormal : UIControlStateDisabled]; \
                [[[JailbreakViewController sharedController] goButton] layoutIfNeeded]; \
            }]; \
        }); \
} while (false)

int stage = __COUNTER__;
extern int maxStage;

#define STATUSWITHSTAGE(Stage, MaxStage) STATUS(([NSString stringWithFormat:@"%@ (%d/%d)", NSLocalizedString(@"Exploiting", nil), Stage, MaxStage]), false, false)
#define UPSTAGE() do { \
    __COUNTER__; \
    stage++; \
    STATUSWITHSTAGE(stage, maxStage); \
} while (false)

#define FINDOFFSET(x, symbol, critical) do { \
    if (!KERN_POINTER_VALID(GETOFFSET(x))) { \
        SETOFFSET(x, find_symbol(symbol != NULL ? symbol : "_" #x)); \
    } \
    if (!KERN_POINTER_VALID(GETOFFSET(x))) { \
        kptr_t (*_find_ ##x)(void) = dlsym(RTLD_DEFAULT, "find_" #x); \
        if (_find_ ##x != NULL) { \
            SETOFFSET(x, _find_ ##x()); \
        } \
    } \
    if (KERN_POINTER_VALID(GETOFFSET(x))) { \
        LOG(#x " = " ADDR " + " ADDR, GETOFFSET(x), kernel_slide); \
        SETOFFSET(x, GETOFFSET(x) + kernel_slide); \
    } else { \
        SETOFFSET(x, 0); \
        if (critical) { \
            _assert(false, message, true); \
        } \
    } \
} while (false)

#define ADDRSTRING(val)        [NSString stringWithFormat:@ADDR, val]

static NSString *bundledResources = nil;

static void writeTestFile(const char *file) {
    _assert(create_file(file, 0, 0644), message, true);
    _assert(clean_file(file), message, true);
}

uint64_t find_gadget_candidate(char **alternatives, size_t gadget_length) {
    auto const haystack_start = (void *)atoi; // will do...
    auto haystack_size = 100*1024*1024; // likewise...
    
    for (char *candidate = *alternatives; candidate != NULL; alternatives++) {
        void *found_at = memmem(haystack_start, haystack_size, candidate, gadget_length);
        if (found_at != NULL){
            LOG("found at: %llx", (uint64_t)found_at);
            return (uint64_t)found_at;
        }
    }
    return 0;
}

uint64_t blr_x19_addr = 0;
uint64_t find_blr_x19_gadget()
{
    if (blr_x19_addr != 0){
        return blr_x19_addr;
    }
    auto const blr_x19 = "\x60\x02\x3f\xd6";
    char* candidates[] = {blr_x19, NULL};
    blr_x19_addr = find_gadget_candidate(candidates, 4);
    return blr_x19_addr;
}

void jailbreak()
{
    auto rv = 0;
    auto usedPersistedKernelTaskPort = NO;
    auto const myPid = getpid();
    auto const myUid = getuid();
    auto myHost = HOST_NULL;
    auto myOriginalHost = HOST_NULL;
    auto myProcAddr = KPTR_NULL;
    auto myOriginalCredAddr = KPTR_NULL;
    auto myCredAddr = KPTR_NULL;
    auto kernelCredAddr = KPTR_NULL;
    auto Shenanigans = KPTR_NULL;
    auto prefs = copy_prefs();
    auto needStrap = NO;
    auto needSubstrate = NO;
    auto skipSubstrate = NO;
    auto const homeDirectory = NSHomeDirectory();
    auto debsToInstall = [NSMutableArray new];
    auto status = [NSMutableString new];
    auto const betaFirmware = isBetaFirmware();
    auto const start_time = time(NULL);
    auto hud = addProgressHUD();
#define INSERTSTATUS(x) do { [status appendString:x]; } while (false)
#define PROGRESS(x) do { LOG("Progress: %@", x); updateProgressHUD(hud, x); } while (false)
    
    UPSTAGE();
    
    {
        // Exploit kernel.
        
        PROGRESS(NSLocalizedString(@"Exploiting kernel...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to exploit kernel.", nil));
        auto exploit_success = NO;
        myHost = mach_host_self();
        _assert(MACH_PORT_VALID(myHost), message, true);
        myOriginalHost = myHost;
        if (restore_kernel_task_port(&tfp0) &&
            restore_kernel_base(&kernel_base, &kernel_slide) &&
            restore_kernel_offset_cache()) {
            usedPersistedKernelTaskPort = YES;
            exploit_success = YES;
        } else {
            switch (prefs->exploit) {
                case empty_list_exploit: {
                    if (vfs_sploit() &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base = find_kernel_base())) {
                        exploit_success = YES;
                    }
                    break;
                }
                case multi_path_exploit: {
                    if (mptcp_go() &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base = find_kernel_base())) {
                        exploit_success = YES;
                    }
                    break;
                }
                case async_wake_exploit: {
                    if (async_wake_go() &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base = find_kernel_base())) {
                        exploit_success = YES;
                    }
                    break;
                }
                case voucher_swap_exploit: {
                    voucher_swap();
                    if (MACH_PORT_VALID(tfp0) &&
                        kernel_slide_init() &&
                        kernel_slide != -1 &&
                        KERN_POINTER_VALID(kernel_base = (kernel_slide + STATIC_KERNEL_BASE_ADDRESS))) {
                        exploit_success = YES;
                    }
                    break;
                }
                case mach_swap_exploit: {
                    auto const machswap_offsets = get_machswap_offsets();
                    if (machswap_offsets != NULL &&
                        machswap_exploit(machswap_offsets) == ERR_SUCCESS &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base)) {
                        exploit_success = YES;
                    }
                    break;
                }
                case mach_swap_2_exploit: {
                    auto const machswap_offsets = get_machswap_offsets();
                    if (machswap_offsets != NULL &&
                        machswap2_exploit(machswap_offsets) == ERR_SUCCESS &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base)) {
                        exploit_success = YES;
                    }
                    break;
                }
                default: {
                    NOTICE(NSLocalizedString(@"No exploit selected.", nil), false, false);
                    STATUS(NSLocalizedString(@"Jailbreak", nil), true, true);
                    return;
                    break;
                }
            }
        }
        if (kernel_slide == -1 && kernel_base != -1) kernel_slide = (kernel_base - STATIC_KERNEL_BASE_ADDRESS);
        LOG("tfp0: 0x%x", tfp0);
        LOG("kernel_base: " ADDR, kernel_base);
        LOG("kernel_slide: " ADDR, kernel_slide);
        if (exploit_success && !verify_tfp0()) {
            LOG("Failed to verify TFP0.");
            exploit_success = NO;
        }
        if (exploit_success && ReadKernel32(kernel_base) != MACH_HEADER_MAGIC) {
            LOG("Failed to verify kernel_base.");
            exploit_success = NO;
        }
        if (!exploit_success) {
            NOTICE(NSLocalizedString(@"Failed to exploit kernel. This is not an error. Reboot and try again.", nil), true, false);
            exit(EXIT_FAILURE);
            _assert(false, message, true);
        }
        INSERTSTATUS(NSLocalizedString(@"Exploited kernel.\n", nil));
        LOG("Successfully exploited kernel.");
    }
    
    UPSTAGE();
    
    {
        if (!found_offsets) {
            // Initialize patchfinder.
            
            PROGRESS(NSLocalizedString(@"Initializing patchfinder...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to initialize patchfinder.", nil));
            auto const original_kernel_cache_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
            auto const decompressed_kernel_cache_path = [homeDirectory stringByAppendingPathComponent:@"Documents/kernelcache.dec"].UTF8String;
            if (!canRead(decompressed_kernel_cache_path)) {
                auto const original_kernel_cache = fopen(original_kernel_cache_path, "rb");
                _assert(original_kernel_cache != NULL, message, true);
                auto const decompressed_kernel_cache = fopen(decompressed_kernel_cache_path, "w+b");
                _assert(decompressed_kernel_cache != NULL, message, true);
                _assert(decompress_kernel(original_kernel_cache, decompressed_kernel_cache, NULL, true) == ERR_SUCCESS, message, true);
                fclose(decompressed_kernel_cache);
                fclose(original_kernel_cache);
            }
            auto kernelVersion = getKernelVersion();
            _assert(kernelVersion != NULL, message, true);
            if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS ||
                find_strref(kernelVersion, 1, string_base_const, true, false) == KPTR_NULL) {
                _assert(clean_file(decompressed_kernel_cache_path), message, true);
                _assert(false, message, true);
            }
            SafeFreeNULL(kernelVersion);
            LOG("Successfully initialized patchfinder.");
        } else {
            auth_ptrs = GETOFFSET(auth_ptrs);
            monolithic_kernel = GETOFFSET(monolithic_kernel);
        }
        if (auth_ptrs) {
            SETOFFSET(auth_ptrs, true);
            LOG("Detected authentication pointers.");
            pmap_load_trust_cache = _pmap_load_trust_cache;
            prefs->ssh_only = true;
            _assert(set_prefs(prefs), message, true);
        }
        if (monolithic_kernel) {
            SETOFFSET(monolithic_kernel, true);
            LOG("Detected monolithic kernel.");
        }
        offset_options = GETOFFSET(unrestrict-options);
        if (!offset_options) {
            offset_options = kmem_alloc(sizeof(kptr_t));
            wk64(offset_options, KPTR_NULL);
            SETOFFSET(unrestrict-options, offset_options);
        }
        if (prefs->enable_get_task_allow) {
            SETOPT(GET_TASK_ALLOW);
        } else {
            UNSETOPT(GET_TASK_ALLOW);
        }
        if (prefs->set_cs_debugged) {
            SETOPT(CS_DEBUGGED);
        } else {
            UNSETOPT(CS_DEBUGGED);
        }
    }

    UPSTAGE();
    
    if (!found_offsets) {
        // Find offsets.
        
        PROGRESS(NSLocalizedString(@"Finding offsets...", nil));
        SETOFFSET(kernel_base, kernel_base);
        SETOFFSET(kernel_slide, kernel_slide);
        FINDOFFSET(trustcache, NULL, true);
        FINDOFFSET(OSBoolean_True, NULL, true);
        FINDOFFSET(osunserializexml, NULL, true);
        FINDOFFSET(smalloc, NULL, true);
        if (!auth_ptrs) {
            FINDOFFSET(add_x0_x0_0x40_ret, NULL, true);
        }
        FINDOFFSET(zone_map_ref, NULL, true);
        FINDOFFSET(vfs_context_current, NULL, true);
        FINDOFFSET(vnode_lookup, NULL, true);
        FINDOFFSET(vnode_put, NULL, true);
        FINDOFFSET(kernel_task, NULL, true);
        FINDOFFSET(shenanigans, NULL, true);
        if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
            FINDOFFSET(vnode_get_snapshot, NULL, true);
            FINDOFFSET(fs_lookup_snapshot_metadata_by_name_and_return_name, NULL, true);
            FINDOFFSET(apfs_jhash_getvnode, NULL, true);
        }
        if (auth_ptrs) {
            FINDOFFSET(pmap_load_trust_cache, NULL, true);
            FINDOFFSET(paciza_pointer__l2tp_domain_module_start, NULL, true);
            FINDOFFSET(paciza_pointer__l2tp_domain_module_stop, NULL, true);
            FINDOFFSET(l2tp_domain_inited, NULL, true);
            FINDOFFSET(sysctl__net_ppp_l2tp, NULL, true);
            FINDOFFSET(sysctl_unregister_oid, NULL, true);
            FINDOFFSET(mov_x0_x4__br_x5, NULL, true);
            FINDOFFSET(mov_x9_x0__br_x1, NULL, true);
            FINDOFFSET(mov_x10_x3__br_x6, NULL, true);
            FINDOFFSET(kernel_forge_pacia_gadget, NULL, true);
            FINDOFFSET(kernel_forge_pacda_gadget, NULL, true);
            FINDOFFSET(IOUserClient__vtable, NULL, true);
            FINDOFFSET(IORegistryEntry__getRegistryEntryID, NULL, true);
        }
        FINDOFFSET(lck_mtx_lock, NULL, true);
        FINDOFFSET(lck_mtx_unlock, NULL, true);
        FINDOFFSET(proc_find, NULL, true);
        FINDOFFSET(proc_rele, NULL, true);
        FINDOFFSET(extension_create_file, NULL, true);
        FINDOFFSET(extension_add, NULL, true);
        FINDOFFSET(extension_release, NULL, true);
        FINDOFFSET(sfree, NULL, true);
        FINDOFFSET(sstrdup, NULL, true);
        FINDOFFSET(strlen, NULL, true);
        found_offsets = true;
        LOG("Successfully found offsets.");

        // Deinitialize patchfinder.
        term_kernel();
    }
    
    UPSTAGE();
    
    {
        // Initialize jailbreak.
        auto const ShenanigansPatch = (kptr_t)0xca13feba37be;
        
        PROGRESS(NSLocalizedString(@"Initializing jailbreak...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to initialize jailbreak.", nil));
        LOG("Escaping sandbox...");
        myProcAddr = get_proc_struct_for_pid(myPid);
        LOG("myProcAddr = " ADDR, myProcAddr);
        _assert(KERN_POINTER_VALID(myProcAddr), message, true);
        kernelCredAddr = get_kernel_cred_addr();
        LOG("kernelCredAddr = " ADDR, kernelCredAddr);
        _assert(KERN_POINTER_VALID(kernelCredAddr), message, true);
        Shenanigans = ReadKernel64(GETOFFSET(shenanigans));
        LOG("Shenanigans = " ADDR, Shenanigans);
        _assert(KERN_POINTER_VALID(Shenanigans) || Shenanigans == ShenanigansPatch, message, true);
        if (Shenanigans != kernelCredAddr) {
            LOG("Detected corrupted shenanigans pointer.");
            Shenanigans = kernelCredAddr;
        }
        _assert(WriteKernel64(GETOFFSET(shenanigans), ShenanigansPatch), message, true);
        myCredAddr = kernelCredAddr;
        myOriginalCredAddr = give_creds_to_process_at_addr(myProcAddr, myCredAddr);
        LOG("myOriginalCredAddr = " ADDR, myOriginalCredAddr);
        _assert(KERN_POINTER_VALID(myOriginalCredAddr), message, true);
        _assert(setuid(0) == ERR_SUCCESS, message, true);
        _assert(getuid() == 0, message, true);
        myHost = mach_host_self();
        _assert(MACH_PORT_VALID(myHost), message, true);
        LOG("Successfully escaped sandbox.");
        LOG("Setting HSP4 as TFP0...");
        _assert(set_hsp4(tfp0), message, true);
        _assert(set_all_image_info_addr_and_size(), message, true);
        LOG("Successfully set HSP4 as TFP0.");
        INSERTSTATUS(NSLocalizedString(@"Set HSP4 as TFP0.\n", nil));
        LOG("Initializing kexecute...");
        _assert(init_kexecute(), message, true);
        LOG("Successfully initialized kexecute.");
        LOG("Platformizing...");
        _assert(set_platform_binary(myProcAddr, true), message, true);
        _assert(set_cs_platform_binary(myProcAddr, true), message, true);
        LOG("Successfully initialized jailbreak.");
    }
    
    UPSTAGE();
    
    {
        if (prefs->export_kernel_task_port) {
            // Export kernel task port.
            PROGRESS(NSLocalizedString(@"Exporting kernel task port...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to export kernel task port.", nil));
            _assert(export_tfp0(myOriginalHost), message, true);
            LOG("Successfully exported kernel task port.");
            INSERTSTATUS(NSLocalizedString(@"Exported kernel task port.\n", nil));
        } else {
            // Unexport kernel task port.
            PROGRESS(NSLocalizedString(@"Unexporting kernel task port...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to unexport kernel task port.", nil));
            _assert(unexport_tfp0(myOriginalHost), message, true);
            LOG("Successfully unexported kernel task port.");
            INSERTSTATUS(NSLocalizedString(@"Unexported kernel task port.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        // Write a test file to UserFS.
        
        PROGRESS(NSLocalizedString(@"Writing a test file to UserFS...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to write a test file to UserFS.", nil));
        auto const testFile = [NSString stringWithFormat:@"/var/mobile/test-%lu.txt", time(NULL)].UTF8String;
        writeTestFile(testFile);
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    UPSTAGE();
    
    {
        if (prefs->dump_apticket) {
            auto const originalFile = @"/System/Library/Caches/apticket.der";
            auto const dumpFile = [homeDirectory stringByAppendingPathComponent:@"Documents/apticket.der"];
            if (![sha1sum(originalFile) isEqualToString:sha1sum(dumpFile)]) {
                // Dump APTicket.
                
                PROGRESS(NSLocalizedString(@"Dumping APTicket...", nil));
                SETMESSAGE(NSLocalizedString(@"Failed to dump APTicket.", nil));
                auto const fileData = [NSData dataWithContentsOfFile:originalFile];
                _assert(([fileData writeToFile:dumpFile atomically:YES]), message, true);
                LOG("Successfully dumped APTicket.");
            }
            INSERTSTATUS(NSLocalizedString(@"Dumped APTicket.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs->overwrite_boot_nonce) {
            // Unlock nvram.
            
            PROGRESS(NSLocalizedString(@"Unlocking nvram...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to unlock nvram.", nil));
            _assert(unlocknvram() == ERR_SUCCESS, message, true);
            LOG("Successfully unlocked nvram.");
            
            _assert(runCommand("/usr/sbin/nvram", "-p", NULL) == ERR_SUCCESS, message, true);
            auto const bootNonceKey = "com.apple.System.boot-nonce";
            if (runCommand("/usr/sbin/nvram", bootNonceKey, NULL) != ERR_SUCCESS ||
                strstr(lastSystemOutput.bytes, prefs->boot_nonce) == NULL) {
                // Set boot-nonce.
                
                PROGRESS(NSLocalizedString(@"Setting boot-nonce...", nil));
                SETMESSAGE(NSLocalizedString(@"Failed to set boot-nonce.", nil));
                _assert(runCommand("/usr/sbin/nvram", [NSString stringWithFormat:@"%s=%s", bootNonceKey, prefs->boot_nonce].UTF8String, NULL) == ERR_SUCCESS, message, true);
                _assert(runCommand("/usr/sbin/nvram", [NSString stringWithFormat:@"%s=%s", kIONVRAMForceSyncNowPropertyKey, bootNonceKey].UTF8String, NULL) == ERR_SUCCESS, message, true);
                LOG("Successfully set boot-nonce.");
            }
            _assert(runCommand("/usr/sbin/nvram", "-p", NULL) == ERR_SUCCESS, message, true);
            
            // Lock nvram.
            
            PROGRESS(NSLocalizedString(@"Locking nvram...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to lock nvram.", nil));
            _assert(locknvram() == ERR_SUCCESS, message, true);
            LOG("Successfully locked nvram.");
            
            INSERTSTATUS(NSLocalizedString(@"Overwrote boot nonce.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        // Log slide.
        
        PROGRESS(NSLocalizedString(@"Logging slide...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to log slide.", nil));
        auto const file = @(SLIDE_FILE);
        auto const fileData = [[NSString stringWithFormat:@(ADDR "\n"), kernel_slide] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:file] isEqual:fileData]) {
            _assert(clean_file(file.UTF8String), message, true);
            _assert(create_file_data(file.UTF8String, 0, 0644, fileData), message, true);
        }
        LOG("Successfully logged slide.");
        INSERTSTATUS(NSLocalizedString(@"Logged slide.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Log ECID.
        
        PROGRESS(NSLocalizedString(@"Logging ECID...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to log ECID.", nil));
        auto const ECID = getECID();
        if (ECID != nil) {
            prefs->ecid = ECID.UTF8String;
            _assert(set_prefs(prefs), message, true);
        } else {
            LOG("I couldn't get the ECID... Am I running on a real device?");
        }
        LOG("Successfully logged ECID.");
        INSERTSTATUS(NSLocalizedString(@"Logged ECID.\n", nil));
    }
    
    UPSTAGE();
    
    {
        auto const array = @[@"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate",
                             @"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation",
                             @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate",
                             @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation"];
        if (prefs->disable_auto_updates) {
            // Disable Auto Updates.
            
            PROGRESS(NSLocalizedString(@"Disabling Auto Updates...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to disable auto updates.", nil));
            for (id path in array) {
                ensure_symlink("/dev/null", [path UTF8String]);
            }
            _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.Preferences.plist", ^(id plist) {
                plist[@"kBadgedForSoftwareUpdateKey"] = @NO;
                plist[@"kBadgedForSoftwareUpdateJumpOnceKey"] = @NO;
            }), message, true);
            LOG("Successfully disabled Auto Updates.");
            INSERTSTATUS(NSLocalizedString(@"Disabled Auto Updates.\n", nil));
        } else {
            // Enable Auto Updates.
            
            PROGRESS(NSLocalizedString(@"Enabling Auto Updates...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to enable auto updates.", nil));
            for (id path in array) {
                ensure_directory([path UTF8String], 0, 0755);
            }
            _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.Preferences.plist", ^(id plist) {
                plist[@"kBadgedForSoftwareUpdateKey"] = @YES;
                plist[@"kBadgedForSoftwareUpdateJumpOnceKey"] = @YES;;
            }), message, true);
            INSERTSTATUS(NSLocalizedString(@"Enabled Auto Updates.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        // Remount RootFS.
        
        PROGRESS(NSLocalizedString(@"Remounting RootFS...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to remount RootFS.", nil));
        auto rootfd = open("/", O_RDONLY);
        _assert(rootfd > 0, message, true);
        auto snapshots = snapshot_list(rootfd);
        auto systemSnapshot = copySystemSnapshot();
        _assert(systemSnapshot != NULL, message, true);
        auto const original_snapshot = "orig-fs";
        auto has_original_snapshot = NO;
        auto const thedisk = "/dev/disk0s1s1";
        auto oldest_snapshot = NULL;
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, message, false);
        if (snapshots == NULL) {
            close(rootfd);
            
            // Clear dev vnode's si_flags.
            
            LOG("Clearing dev vnode's si_flags...");
            SETMESSAGE(NSLocalizedString(@"Failed to clear dev vnode's si_flags.", nil));
            auto devVnode = get_vnode_for_path(thedisk);
            LOG("devVnode = " ADDR, devVnode);
            _assert(KERN_POINTER_VALID(devVnode), message, true);
            auto v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
            LOG("v_specinfo = " ADDR, v_specinfo);
            _assert(KERN_POINTER_VALID(v_specinfo), message, true);
            WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
            _assert(vnode_put(devVnode) == ERR_SUCCESS, message, true);
            LOG("Successfully cleared dev vnode's si_flags.");
            
            // Mount RootFS.
            
            LOG("Mounting RootFS...");
            SETMESSAGE(NSLocalizedString(@"Unable to mount RootFS.", nil));
            auto const invalidRootMessage = NSLocalizedString(@"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot.", nil);
            _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"), invalidRootMessage, true);
            auto const rootFsMountPoint = "/private/var/tmp/jb/mnt1";
            if (is_mountpoint(rootFsMountPoint)) {
                _assert(unmount(rootFsMountPoint, MNT_FORCE) == ERR_SUCCESS, message, true);
            }
            _assert(clean_file(rootFsMountPoint), message, true);
            _assert(ensure_directory(rootFsMountPoint, 0, 0755), message, true);
            const char *argv[] = {"/sbin/mount_apfs", thedisk, rootFsMountPoint, NULL};
            _assert(runCommandv(argv[0], 3, argv, ^(pid_t pid) {
                auto const procStructAddr = get_proc_struct_for_pid(pid);
                LOG("procStructAddr = " ADDR, procStructAddr);
                _assert(KERN_POINTER_VALID(procStructAddr), message, true);
                give_creds_to_process_at_addr(procStructAddr, kernelCredAddr);
            }) == ERR_SUCCESS, message, true);
            _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, message, true);
            auto const systemSnapshotLaunchdPath = [@(rootFsMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, message, true);
            LOG("Successfully mounted RootFS.");
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Unable to rename system snapshot. Delete OTA file from Settings - Storage if present and reboot.", nil));
            rootfd = open(rootFsMountPoint, O_RDONLY);
            _assert(rootfd > 0, message, true);
            snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, message, true);
            LOG("Snapshots on newly mounted RootFS:");
            for (auto snapshot = snapshots; *snapshot; snapshot++) {
                LOG("\t%s", *snapshot);
            }
            SafeFreeNULL(snapshots);
            auto const systemVersionPlist = @"/System/Library/CoreServices/SystemVersion.plist";
            auto const rootSystemVersionPlist = [@(rootFsMountPoint) stringByAppendingPathComponent:systemVersionPlist];
            _assert(rootSystemVersionPlist != nil, message, true);
            auto const snapshotSystemVersion = [NSDictionary dictionaryWithContentsOfFile:systemVersionPlist];
            _assert(snapshotSystemVersion != nil, message, true);
            auto const rootfsSystemVersion = [NSDictionary dictionaryWithContentsOfFile:rootSystemVersionPlist];
            _assert(rootfsSystemVersion != nil, message, true);
            if (![rootfsSystemVersion[@"ProductBuildVersion"] isEqualToString:snapshotSystemVersion[@"ProductBuildVersion"]]) {
                LOG("snapshot VersionPlist: %@", snapshotSystemVersion);
                LOG("rootfs VersionPlist: %@", rootfsSystemVersion);
                _assert("BuildVersions match"==NULL, invalidRootMessage, true);
            }
            auto const test_snapshot = "test-snapshot";
            _assert(fs_snapshot_create(rootfd, test_snapshot, 0) == ERR_SUCCESS, message, true);
            _assert(fs_snapshot_delete(rootfd, test_snapshot, 0) == ERR_SUCCESS, message, true);
            auto system_snapshot_vnode = KPTR_NULL;
            auto system_snapshot_vnode_v_data = KPTR_NULL;
            auto system_snapshot_vnode_v_data_flag = 0;
            if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
                system_snapshot_vnode = get_vnode_for_snapshot(rootfd, systemSnapshot);
                LOG("system_snapshot_vnode = " ADDR, system_snapshot_vnode);
                _assert(KERN_POINTER_VALID(system_snapshot_vnode), message, true);
                system_snapshot_vnode_v_data = ReadKernel64(system_snapshot_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_DATA));
                LOG("system_snapshot_vnode_v_data = " ADDR, system_snapshot_vnode_v_data);
                _assert(KERN_POINTER_VALID(system_snapshot_vnode_v_data), message, true);
                system_snapshot_vnode_v_data_flag = ReadKernel32(system_snapshot_vnode_v_data + 49);
                LOG("system_snapshot_vnode_v_data_flag = 0x%x", system_snapshot_vnode_v_data_flag);
                WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag & ~0x40);
            }
            _assert(fs_snapshot_rename(rootfd, systemSnapshot, original_snapshot, 0) == ERR_SUCCESS, message, true);
            if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
                WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag);
                _assert(vnode_put(system_snapshot_vnode) == ERR_SUCCESS, message, true);
            }
            LOG("Successfully renamed system snapshot.");
            
            // Reboot.
            close(rootfd);
            
            LOG("Rebooting...");
            SETMESSAGE(NSLocalizedString(@"Failed to reboot.", nil));
            NOTICE(NSLocalizedString(@"The system snapshot has been successfully renamed. The device will now be restarted.", nil), true, false);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, message, true);
            _assert(false, message, true);
            LOG("Successfully rebooted.");
        } else {
            LOG("APFS Snapshots:");
            for (auto snapshot = snapshots; *snapshot; snapshot++) {
                if (oldest_snapshot == NULL) {
                    oldest_snapshot = strdup(*snapshot);
                }
                if (strcmp(original_snapshot, *snapshot) == 0) {
                    has_original_snapshot = YES;
                }
                LOG("%s", *snapshot);
            }
        }
        
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, message, false);
        auto rootfs_vnode = get_vnode_for_path("/");
        LOG("rootfs_vnode = " ADDR, rootfs_vnode);
        _assert(KERN_POINTER_VALID(rootfs_vnode), message, true);
        auto v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
        LOG("v_mount = " ADDR, v_mount);
        _assert(KERN_POINTER_VALID(v_mount), message, true);
        auto v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
        if ((v_flag & MNT_RDONLY) || (v_flag & MNT_NOSUID)) {
            v_flag &= ~(MNT_RDONLY | MNT_NOSUID);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
            auto opts = strdup(thedisk);
            _assert(opts != NULL, message, true);
            _assert(mount("apfs", "/", MNT_UPDATE, (void *)&opts) == ERR_SUCCESS, message, true);
            SafeFreeNULL(opts);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
        }
        _assert(vnode_put(rootfs_vnode) == ERR_SUCCESS, message, true);
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, message, false);
        auto const file = [NSString stringWithContentsOfFile:@"/.installed_unc0ver" encoding:NSUTF8StringEncoding error:nil];
        needStrap = file == nil;
        needStrap |= ![file isEqualToString:@""] && ![file isEqualToString:[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber]];
        needStrap &= access("/electra", F_OK) != ERR_SUCCESS;
        needStrap &= access("/chimera", F_OK) != ERR_SUCCESS;
        if (needStrap)
            LOG("We need strap.");
        if (!has_original_snapshot) {
            if (oldest_snapshot != NULL) {
                _assert(fs_snapshot_rename(rootfd, oldest_snapshot, original_snapshot, 0) == ERR_SUCCESS, message, true);
            } else if (needStrap) {
                _assert(fs_snapshot_create(rootfd, original_snapshot, 0) == ERR_SUCCESS, message, true);
            }
        }
        close(rootfd);
        SafeFreeNULL(snapshots);
        SafeFreeNULL(systemSnapshot);
        SafeFreeNULL(oldest_snapshot);
        LOG("Successfully remounted RootFS.");
        INSERTSTATUS(NSLocalizedString(@"Remounted RootFS.\n", nil));
    }

    UPSTAGE();
    
    {
        // Write a test file to RootFS.
        
        PROGRESS(NSLocalizedString(@"Writing a test file to RootFS...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to write a test file to RootFS.", nil));
        auto const testFile = [NSString stringWithFormat:@"/test-%lu.txt", time(NULL)].UTF8String;
        writeTestFile(testFile);
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    UPSTAGE();
    
    {
        auto const array = @[@"/var/Keychains/ocspcache.sqlite3",
                             @"/var/Keychains/ocspcache.sqlite3-shm",
                             @"/var/Keychains/ocspcache.sqlite3-wal"];
        if (prefs->disable_app_revokes && kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_12_0) {
            // Disable app revokes.
            PROGRESS(NSLocalizedString(@"Disabling app revokes...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to disable app revokes.", nil));
            blockDomainWithName("ocsp.apple.com");
            for (id path in array) {
                ensure_symlink("/dev/null", [path UTF8String]);
            }
            LOG("Successfully disabled app revokes.");
            INSERTSTATUS(NSLocalizedString(@"Disabled App Revokes.\n", nil));
        } else {
            // Enable app revokes.
            PROGRESS(NSLocalizedString(@"Enabling app revokes...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to enable app revokes.", nil));
            unblockDomainWithName("ocsp.apple.com");
            for (id path in array) {
                if (is_symlink([path UTF8String])) {
                    clean_file([path UTF8String]);
                }
            }
            LOG("Successfully enabled app revokes.");
            INSERTSTATUS(NSLocalizedString(@"Enabled App Revokes.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        // Create jailbreak directory.
        
        PROGRESS(NSLocalizedString(@"Creating jailbreak directory...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to create jailbreak directory.", nil));
        _assert(ensure_directory("/jb", 0, 0755), message, true);
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
        LOG("Successfully created jailbreak directory.");
        INSERTSTATUS(NSLocalizedString(@"Created jailbreak directory.\n", nil));
    }
    
    UPSTAGE();
    
    {
        auto const offsetsFile = @"/jb/offsets.plist";
        auto dictionary = [NSMutableDictionary new];
#define CACHEADDR(value, name) do { \
    dictionary[@(name)] = ADDRSTRING(value); \
} while (false)
#define CACHEOFFSET(offset, name) CACHEADDR(GETOFFSET(offset), name)
        CACHEADDR(kernel_base, "KernelBase");
        CACHEADDR(kernel_slide, "KernelSlide");
        CACHEOFFSET(trustcache, "TrustChain");
        CACHEADDR(ReadKernel64(GETOFFSET(OSBoolean_True)), "OSBooleanTrue");
        CACHEADDR(ReadKernel64(GETOFFSET(OSBoolean_True)) + sizeof(kptr_t), "OSBooleanFalse");
        CACHEOFFSET(osunserializexml, "OSUnserializeXML");
        CACHEOFFSET(smalloc, "Smalloc");
        CACHEOFFSET(add_x0_x0_0x40_ret, "AddRetGadget");
        CACHEOFFSET(zone_map_ref, "ZoneMapOffset");
        CACHEOFFSET(vfs_context_current, "VfsContextCurrent");
        CACHEOFFSET(vnode_lookup, "VnodeLookup");
        CACHEOFFSET(vnode_put, "VnodePut");
        CACHEOFFSET(kernel_task, "KernelTask");
        CACHEOFFSET(shenanigans, "Shenanigans");
        CACHEOFFSET(lck_mtx_lock, "LckMtxLock");
        CACHEOFFSET(lck_mtx_unlock, "LckMtxUnlock");
        CACHEOFFSET(vnode_get_snapshot, "VnodeGetSnapshot");
        CACHEOFFSET(fs_lookup_snapshot_metadata_by_name_and_return_name, "FsLookupSnapshotMetadataByNameAndReturnName");
        CACHEOFFSET(pmap_load_trust_cache, "PmapLoadTrustCache");
        CACHEOFFSET(apfs_jhash_getvnode, "APFSJhashGetVnode");
        CACHEOFFSET(paciza_pointer__l2tp_domain_module_start, "PacizaPointerL2TPDomainModuleStart");
        CACHEOFFSET(paciza_pointer__l2tp_domain_module_stop, "PacizaPointerL2TPDomainModuleStop");
        CACHEOFFSET(l2tp_domain_inited, "L2TPDomainInited");
        CACHEOFFSET(sysctl__net_ppp_l2tp, "SysctlNetPPPL2TP");
        CACHEOFFSET(sysctl_unregister_oid, "SysctlUnregisterOid");
        CACHEOFFSET(mov_x0_x4__br_x5, "MovX0X4BrX5");
        CACHEOFFSET(mov_x9_x0__br_x1, "MovX9X0BrX1");
        CACHEOFFSET(mov_x10_x3__br_x6, "MovX10X3BrX6");
        CACHEOFFSET(kernel_forge_pacia_gadget, "KernelForgePaciaGadget");
        CACHEOFFSET(kernel_forge_pacda_gadget, "KernelForgePacdaGadget");
        CACHEOFFSET(IOUserClient__vtable, "IOUserClientVtable");
        CACHEOFFSET(IORegistryEntry__getRegistryEntryID, "IORegistryEntryGetRegistryEntryID");
        CACHEOFFSET(proc_find, "ProcFind");
        CACHEOFFSET(proc_rele, "ProcRele");
        CACHEOFFSET(extension_create_file, "ExtensionCreateFile");
        CACHEOFFSET(extension_add, "ExtensionAdd");
        CACHEOFFSET(extension_release, "ExtensionRelease");
        CACHEOFFSET(sfree, "Sfree");
        CACHEOFFSET(sstrdup, "Sstrdup");
        CACHEOFFSET(strlen, "Strlen");
#undef CACHEOFFSET
#undef CACHEADDR
        if (![[NSMutableDictionary dictionaryWithContentsOfFile:offsetsFile] isEqual:dictionary]) {
            // Cache offsets.
            
            PROGRESS(NSLocalizedString(@"Caching offsets...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to cache offsets.", nil));
            _assert(([dictionary writeToFile:offsetsFile atomically:YES]), message, true);
            _assert(init_file(offsetsFile.UTF8String, 0, 0644), message, true);
            LOG("Successfully cached offsets.");
            INSERTSTATUS(NSLocalizedString(@"Cached Offsets.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs->restore_rootfs) {
            PROGRESS(NSLocalizedString(@"Restoring RootFS...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to Restore RootFS.", nil));
            NOTICE(NSLocalizedString(@"Will restore RootFS. This may take a while. Don't exit the app and don't let the device lock.", nil), 1, 1);
            
            LOG("Reverting back RootFS remount...");
            auto const rootfd = open("/", O_RDONLY);
            _assert(rootfd > 0, message, true);
            auto snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, message, true);
            auto const snapshot = *snapshots;
            LOG("%s", snapshot);
            _assert(snapshot != NULL, message, true);
            auto const systemSnapshotMountPoint = "/private/var/tmp/jb/mnt2";
            if (is_mountpoint(systemSnapshotMountPoint)) {
                _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, message, true);
            }
            _assert(clean_file(systemSnapshotMountPoint), message, true);
            _assert(ensure_directory(systemSnapshotMountPoint, 0, 0755), message, true);
            _assert(fs_snapshot_mount(rootfd, systemSnapshotMountPoint, snapshot, 0) == ERR_SUCCESS, message, true);
            auto const systemSnapshotLaunchdPath = [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, message, true);
            _assert(extractDebsForPkg(@"rsync", nil, false), message, true);
            _assert(extractDebsForPkg(@"uikittools", nil, false), message, true);
            _assert(injectTrustCache(@[@"/usr/bin/rsync", @"/usr/bin/uicache"], GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, message, true);
            if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_11_3) {
                _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete-after", "--exclude=/Developer", "--exclude=/usr/bin/uicache", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"."].UTF8String, "/", NULL) == 0, message, true);
            } else {
                _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete-after", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"Applications/."].UTF8String, "/Applications", NULL) == 0, message, true);
            }
            _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, message, true);
            if (!(kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_11_3)) {
                auto systemSnapshot = copySystemSnapshot();
                _assert(systemSnapshot != NULL, message, true);
                _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, message, true);
                SafeFreeNULL(systemSnapshot);
            }
            close(rootfd);
            SafeFreeNULL(snapshots);
            _assert(runCommand("/usr/bin/uicache", NULL) == ERR_SUCCESS, message, true);
            _assert(clean_file("/usr/bin/uicache"), message, true);
            LOG("Successfully reverted back RootFS remount.");
            
            // Clean up.
            
            LOG("Cleaning up...");
            SETMESSAGE(NSLocalizedString(@"Failed to clean up.", nil));
            auto const cleanUpFileList = @[@"/var/cache",
                                           @"/var/lib",
                                           @"/var/stash",
                                           @"/var/db/stash",
                                           @"/var/mobile/Library/Cydia",
                                           @"/var/mobile/Library/Caches/com.saurik.Cydia"];
            for (id file in cleanUpFileList) {
                clean_file([file UTF8String]);
            }
            LOG("Successfully cleaned up.");
            
            // Disallow SpringBoard to show non-default system apps.
            
            LOG("Disallowing SpringBoard to show non-default system apps...");
            SETMESSAGE(NSLocalizedString(@"Failed to disallow SpringBoard to show non-default system apps.", nil));
            _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
                plist[@"SBShowNonDefaultSystemApps"] = @NO;
            }), message, true);
            LOG("Successfully disallowed SpringBoard to show non-default system apps.");
            
            // Disable RootFS Restore.
            
            LOG("Disabling RootFS Restore...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable RootFS Restore.", nil));
            prefs->restore_rootfs = false;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully disabled RootFS Restore.");
            
            INSERTSTATUS(NSLocalizedString(@"Restored RootFS.\n", nil));
            
            // Reboot.
            
            LOG("Rebooting...");
            SETMESSAGE(NSLocalizedString(@"Failed to reboot.", nil));
            NOTICE(NSLocalizedString(@"RootFS has been successfully restored. The device will now be restarted.", nil), true, false);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, message, true);
            _assert(false, message, true);
            LOG("Successfully rebooted.");
        }
    }
    
    UPSTAGE();
    
    {
        // Allow SpringBoard to show non-default system apps.
        
        PROGRESS(NSLocalizedString(@"Allowing SpringBoard to show non-default system apps...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to allow SpringBoard to show non-default system apps.", nil));
        _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
            plist[@"SBShowNonDefaultSystemApps"] = @YES;
        }), message, true);
        LOG("Successfully allowed SpringBoard to show non-default system apps.");
        INSERTSTATUS(NSLocalizedString(@"Allowed SpringBoard to show non-default system apps.\n", nil));
    }
    
    UPSTAGE();
    
    if (prefs->ssh_only && needStrap) {
        PROGRESS(NSLocalizedString(@"Enabling SSH...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to enable SSH.", nil));
        auto toInject = [NSMutableArray new];
        if (!verifySums(pathForResource(@"binpack64-256.md5sums"), HASHTYPE_MD5)) {
            auto binpack64 = [ArchiveFile archiveWithFile:pathForResource(@"binpack64-256.tar.lzma")];
            _assert(binpack64 != nil, message, true);
            _assert([binpack64 extractToPath:@"/jb"], message, true);
            for (id file in binpack64.files.allKeys) {
                auto const path = [@"/jb" stringByAppendingPathComponent:file];
                if (cdhashFor(path) != nil) {
                    if (![toInject containsObject:path]) {
                        [toInject addObject:path];
                    }
                }
            }
        }
        auto const fileManager = [NSFileManager defaultManager];
        auto directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:@"/jb"] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
        _assert(directoryEnumerator != nil, message, true);
        for (id URL in directoryEnumerator) {
            auto path = [URL path];
            if (cdhashFor(path) != nil) {
                if (![toInject containsObject:path]) {
                    [toInject addObject:path];
                }
            }
        }
        for (id file in [fileManager contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
            auto path = [@"/Applications" stringByAppendingPathComponent:file];
            auto info_plist = [NSMutableDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
            if (info_plist == nil) continue;
            if ([info_plist[@"CFBundleIdentifier"] hasPrefix:@"com.apple."]) continue;
            directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:path] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
            if (directoryEnumerator == nil) continue;
            for (id URL in directoryEnumerator) {
                auto path = [URL path];
                if (cdhashFor(path) != nil) {
                    if (![toInject containsObject:path]) {
                        [toInject addObject:path];
                    }
                }
            }
        }
        if (toInject.count > 0) {
            _assert(injectTrustCache(toInject, GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, message, true);
        }
        _assert(ensure_symlink("/jb/usr/bin/scp", "/usr/bin/scp"), message, true);
        _assert(ensure_directory("/usr/local/lib", 0, 0755), message, true);
        _assert(ensure_directory("/usr/local/lib/zsh", 0, 0755), message, true);
        _assert(ensure_directory("/usr/local/lib/zsh/5.0.8", 0, 0755), message, true);
        _assert(ensure_symlink("/jb/usr/local/lib/zsh/5.0.8/zsh", "/usr/local/lib/zsh/5.0.8/zsh"), message, true);
        _assert(ensure_symlink("/jb/bin/zsh", "/bin/zsh"), message, true);
        _assert(ensure_symlink("/jb/etc/zshrc", "/etc/zshrc"), message, true);
        _assert(ensure_symlink("/jb/usr/share/terminfo", "/usr/share/terminfo"), message, true);
        _assert(ensure_symlink("/jb/usr/local/bin", "/usr/local/bin"), message, true);
        _assert(ensure_symlink("/jb/etc/profile", "/etc/profile"), message, true);
        _assert(ensure_directory("/etc/dropbear", 0, 0755), message, true);
        _assert(ensure_directory("/jb/Library", 0, 0755), message, true);
        _assert(ensure_directory("/jb/Library/LaunchDaemons", 0, 0755), message, true);
        _assert(ensure_directory("/jb/etc/rc.d", 0, 0755), message, true);
        if (access("/jb/Library/LaunchDaemons/dropbear.plist", F_OK) != ERR_SUCCESS) {
            auto dropbear_plist = [NSMutableDictionary new];
            _assert(dropbear_plist, message, true);
            dropbear_plist[@"Program"] = @"/jb/usr/local/bin/dropbear";
            dropbear_plist[@"RunAtLoad"] = @YES;
            dropbear_plist[@"Label"] = @"ShaiHulud";
            dropbear_plist[@"KeepAlive"] = @YES;
            dropbear_plist[@"ProgramArguments"] = [NSMutableArray new];
            dropbear_plist[@"ProgramArguments"][0] = @"/usr/local/bin/dropbear";
            dropbear_plist[@"ProgramArguments"][1] = @"-F";
            dropbear_plist[@"ProgramArguments"][2] = @"-R";
            dropbear_plist[@"ProgramArguments"][3] = @"--shell";
            dropbear_plist[@"ProgramArguments"][4] = @"/jb/bin/bash";
            dropbear_plist[@"ProgramArguments"][5] = @"-p";
            dropbear_plist[@"ProgramArguments"][6] = @"22";
            _assert([dropbear_plist writeToFile:@"/jb/Library/LaunchDaemons/dropbear.plist" atomically:YES], message, true);
            _assert(init_file("/jb/Library/LaunchDaemons/dropbear.plist", 0, 0644), message, true);
        }
        if (prefs->load_daemons) {
            for (id file in [fileManager contentsOfDirectoryAtPath:@"/jb/Library/LaunchDaemons" error:nil]) {
                auto const path = [@"/jb/Library/LaunchDaemons" stringByAppendingPathComponent:file];
                runCommand("/jb/bin/launchctl", "load", path.UTF8String, NULL);
            }
            for (id file in [fileManager contentsOfDirectoryAtPath:@"/jb/etc/rc.d" error:nil]) {
                auto const path = [@"/jb/etc/rc.d" stringByAppendingPathComponent:file];
                if ([fileManager isExecutableFileAtPath:path]) {
                    runCommand("/jb/bin/bash", "-c", path.UTF8String, NULL);
                }
            }
        }
        if (prefs->run_uicache) {
            _assert(runCommand("/jb/usr/bin/uicache", NULL) == ERR_SUCCESS, message, true);
        }
        _assert(runCommand("/jb/bin/launchctl", "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, message, true);
        LOG("Successfully enabled SSH.");
        INSERTSTATUS(NSLocalizedString(@"Enabled SSH.\n", nil));
    }
    
    if (auth_ptrs || prefs->ssh_only) {
        goto out;
    }
    
    UPSTAGE();
    
    {
        // Copy over resources to RootFS.
        
        PROGRESS(NSLocalizedString(@"Copying over resources to RootFS...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to copy over resources to RootFS.", nil));
        
        _assert(chdir("/") == ERR_SUCCESS, message, true);
        
        // Uninstall RootLessJB if it is found to prevent conflicts with dpkg.
        _assert(uninstallRootLessJB(), message, true);
        
        // Make sure we have an apt packages cache
        _assert(ensureAptPkgLists(), message, true);
        
        needSubstrate = ( needStrap ||
                         (access("/usr/libexec/substrate", F_OK) != ERR_SUCCESS) ||
                         !verifySums(@"/var/lib/dpkg/info/mobilesubstrate.md5sums", HASHTYPE_MD5)
                         );
        if (needSubstrate) {
            LOG(@"We need substrate.");
            auto const substrateDeb = debForPkg(@"mobilesubstrate");
            _assert(substrateDeb != nil, message, true);
            if (pidOfProcess("/usr/libexec/substrated") == 0) {
                _assert(extractDeb(substrateDeb), message, true);
            } else {
                skipSubstrate = YES;
                LOG("Substrate is running, not extracting again for now.");
            }
            [debsToInstall addObject:substrateDeb];
        }
        
        auto resourcesPkgs = resolveDepsForPkg(@"jailbreak-resources", true);
        _assert(resourcesPkgs != nil, message, true);
        resourcesPkgs = [@[@"system-memory-reset-fix"] arrayByAddingObjectsFromArray:resourcesPkgs];
        if (betaFirmware) {
            resourcesPkgs = [@[@"com.parrotgeek.nobetaalert"] arrayByAddingObjectsFromArray:resourcesPkgs];
        }
        if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
            resourcesPkgs = [@[@"com.ps.letmeblock"] arrayByAddingObjectsFromArray:resourcesPkgs];
        }

        auto pkgsToRepair = [NSMutableArray new];
        LOG("Resource Pkgs: \"%@\".", resourcesPkgs);
        for (id pkg in resourcesPkgs) {
            // Ignore mobilesubstrate because we just handled that separately.
            if ([pkg isEqualToString:@"mobilesubstrate"] || [pkg isEqualToString:@"firmware"])
                continue;
            if (verifySums([NSString stringWithFormat:@"/var/lib/dpkg/info/%@.md5sums", pkg], HASHTYPE_MD5)) {
                LOG("Pkg \"%@\" verified.", pkg);
            } else {
                LOG(@"Need to repair \"%@\".", pkg);
                if ([pkg isEqualToString:@"signing-certificate"]) {
                    // Hack to make sure it catches the Depends: version if it's already installed
                    [debsToInstall addObject:debForPkg(@"jailbreak-resources")];
                }
                [pkgsToRepair addObject:pkg];
            }
        }
        if (pkgsToRepair.count > 0) {
            LOG(@"(Re-)Extracting \"%@\".", pkgsToRepair);
            auto const debsToRepair = debsForPkgs(pkgsToRepair);
            _assert(debsToRepair.count == pkgsToRepair.count, message, true);
            _assert(extractDebs(debsToRepair), message, true);
            [debsToInstall addObjectsFromArray:debsToRepair];
        }
        
        // Ensure ldid's symlink isn't missing
        // (it's created by update-alternatives which may not have been called yet)
        if (access("/usr/bin/ldid", F_OK) != ERR_SUCCESS) {
            _assert(access("/usr/libexec/ldid", F_OK) == ERR_SUCCESS, message, true);
            _assert(ensure_symlink("../libexec/ldid", "/usr/bin/ldid"), message, true);
        }

        // These don't need to lay around
        clean_file("/Library/LaunchDaemons/jailbreakd.plist");
        clean_file("/jb/jailbreakd.plist");
        clean_file("/jb/amfid_payload.dylib");
        clean_file("/jb/libjailbreak.dylib");
        
        LOG("Successfully copied over resources to RootFS.");
        INSERTSTATUS(NSLocalizedString(@"Copied over resources to RootFS.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Inject trust cache
        
        PROGRESS(NSLocalizedString(@"Injecting trust cache...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to inject trust cache.", nil));
        auto resources = [NSArray arrayWithContentsOfFile:@"/usr/share/jailbreak/injectme.plist"];
        // If substrate is already running but was broken, skip injecting again
        if (!skipSubstrate) {
            resources = [@[@"/usr/libexec/substrate"] arrayByAddingObjectsFromArray:resources];
        }
        resources = [@[@"/usr/libexec/substrated"] arrayByAddingObjectsFromArray:resources];
        for (id file in resources) {
            if (![toInjectToTrustCache containsObject:file]) {
                [toInjectToTrustCache addObject:file];
            }
        }
        _assert(injectTrustCache(toInjectToTrustCache, GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, message, true);
        [toInjectToTrustCache removeAllObjects];
        injectedToTrustCache = true;
        LOG("Successfully injected trust cache.");
        INSERTSTATUS(NSLocalizedString(@"Injected trust cache.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Repair filesystem.
        
        PROGRESS(NSLocalizedString(@"Repairing filesystem...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to repair filesystem.", nil));
        
        _assert(ensure_directory("/var/lib", 0, 0755), message, true);

        // Make sure dpkg is not corrupted
        if (is_directory("/var/lib/dpkg")) {
            if (is_directory("/Library/dpkg")) {
                LOG(@"Removing /var/lib/dpkg...");
                _assert(clean_file("/var/lib/dpkg"), message, true);
            } else {
                LOG(@"Moving /var/lib/dpkg to /Library/dpkg...");
                _assert([[NSFileManager defaultManager] moveItemAtPath:@"/var/lib/dpkg" toPath:@"/Library/dpkg" error:nil], message, true);
            }
        }
        
        _assert(ensure_symlink("/Library/dpkg", "/var/lib/dpkg"), message, true);
        _assert(ensure_directory("/Library/dpkg", 0, 0755), message, true);
        _assert(ensure_file("/var/lib/dpkg/status", 0, 0644), message, true);
        _assert(ensure_file("/var/lib/dpkg/available", 0, 0644), message, true);
        
        // Make sure firmware-sbin package is not corrupted.
        auto file = [NSString stringWithContentsOfFile:@"/var/lib/dpkg/info/firmware-sbin.list" encoding:NSUTF8StringEncoding error:nil];
        if ([file containsString:@"/sbin/fstyp"] || [file containsString:@"\n\n"]) {
            // This is not a stock file for iOS11+
            file = [file stringByReplacingOccurrencesOfString:@"/sbin/fstyp\n" withString:@""];
            file = [file stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
            [file writeToFile:@"/var/lib/dpkg/info/firmware-sbin.list" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        
        // Make sure this is a symlink - usually handled by ncurses pre-inst
        _assert(ensure_symlink("/usr/lib", "/usr/lib/_ncurses"), message, true);
        
        // This needs to be there for Substrate to work properly
        _assert(ensure_directory("/Library/Caches", 0, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), message, true);
        LOG("Successfully repaired filesystem.");
        
        INSERTSTATUS(NSLocalizedString(@"Repaired Filesystem.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Load Substrate
        
        // Set Disable Loader.
        PROGRESS(NSLocalizedString(@"Setting Disable Loader...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to set Disable Loader.", nil));
        if (prefs->load_tweaks) {
            clean_file("/var/tmp/.substrated_disable_loader");
        } else {
            _assert(create_file("/var/tmp/.substrated_disable_loader", 0, 644), message, true);
        }
        LOG("Successfully set Disable Loader.");

        // Run substrate
        PROGRESS(NSLocalizedString(@"Starting Substrate...", nil));
        SETMESSAGE(NSLocalizedString(skipSubstrate?@"Failed to restart Substrate":@"Failed to start Substrate.", nil));
        if (access("/usr/lib/substrate", F_OK) == ERR_SUCCESS && !is_symlink("/usr/lib/substrate")) {
            _assert(clean_file("/Library/substrate"), message, true);
            _assert([[NSFileManager defaultManager] moveItemAtPath:@"/usr/lib/substrate" toPath:@"/Library/substrate" error:nil], message, true);
        }
        _assert(ensure_symlink("/Library/substrate", "/usr/lib/substrate"), message, true);
        _assert(runCommand("/usr/libexec/substrate", NULL) == ERR_SUCCESS, message, skipSubstrate?false:true);
        LOG("Successfully started Substrate.");
        
        INSERTSTATUS(NSLocalizedString(@"Loaded Substrate.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Extract bootstrap.
        PROGRESS(NSLocalizedString(@"Extracting bootstrap...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to extract bootstrap.", nil));

        if (pkgIsBy("CoolStar", "lzma")) {
            removePkg("lzma", true);
            extractDebsForPkg(@"lzma", debsToInstall, false);
            _assert(injectTrustCache(toInjectToTrustCache, GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, message, true);
            [toInjectToTrustCache removeAllObjects];
            injectedToTrustCache = true;
        }
        
        if (pkgIsInstalled("openssl") && compareInstalledVersion("openssl", "lt", "1.0.2q")) {
            removePkg("openssl", true);
        }
        // Test dpkg
        if (!pkgIsConfigured("dpkg") || pkgIsBy("CoolStar", "dpkg")) {
            LOG("Extracting dpkg...");
            _assert(extractDebsForPkg(@"dpkg", debsToInstall, false), message, true);
            _assert(injectTrustCache(toInjectToTrustCache, GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, message, true);
            [toInjectToTrustCache removeAllObjects];
            injectedToTrustCache = true;
            auto const dpkg_deb = debForPkg(@"dpkg");
            _assert(installDeb(dpkg_deb.UTF8String, true), message, true);
            [debsToInstall removeObject:dpkg_deb];
        }
        
        if (needStrap || !pkgIsConfigured("firmware")) {
            LOG("Extracting Cydia...");
            if (access("/usr/libexec/cydia/firmware.sh", F_OK) != ERR_SUCCESS || !pkgIsConfigured("cydia")) {
                auto const fwDebs = debsForPkgs(@[@"cydia", @"cydia-lproj", @"darwintools", @"uikittools", @"system-cmds"]);
                _assert(fwDebs != nil, message, true);
                _assert(installDebs(fwDebs, true), message, true);
                rv = _system("/usr/libexec/cydia/firmware.sh");
                _assert(WEXITSTATUS(rv) == 0, message, true);
            }
        }
        
        // Dpkg better work now
        
        if (pkgIsInstalled("science.xnu.undecimus.resources")) {
            LOG("Removing old resources...");
            _assert(removePkg("science.xnu.undecimus.resources", true), message, true);
        }
        
        if (pkgIsInstalled("jailbreak-resources-with-cert")) {
            LOG("Removing resources-with-cert...");
            _assert(removePkg("jailbreak-resources-with-cert", true), message, true);
        }
            
        if ((pkgIsInstalled("apt7") && compareInstalledVersion("apt7", "lt", "1:0")) ||
            (pkgIsInstalled("apt7-lib") && compareInstalledVersion("apt7-lib", "lt", "1:0")) ||
            (pkgIsInstalled("apt7-key") && compareInstalledVersion("apt7-key", "lt", "1:0"))
            ) {
            LOG("Installing newer version of apt7");
            auto const apt7debs = debsForPkgs(@[@"apt7", @"apt7-key", @"apt7-lib"]);
            _assert(apt7debs != nil && apt7debs.count == 3, message, true);
            for (id deb in apt7debs) {
                if (![debsToInstall containsObject:deb]) {
                    [debsToInstall addObject:deb];
                }
            }
        }
        
        if (debsToInstall.count > 0) {
            LOG("Installing manually exctracted debs...");
            _assert(installDebs(debsToInstall, true), message, true);
        }

        _assert(ensure_directory("/etc/apt/undecimus", 0, 0755), message, true);
        clean_file("/etc/apt/sources.list.d/undecimus.list");
        auto const listPath = "/etc/apt/undecimus/undecimus.list";
        auto const listContents = @"deb file:///var/lib/undecimus/apt ./\n";
        auto const existingList = [NSString stringWithContentsOfFile:@(listPath) encoding:NSUTF8StringEncoding error:nil];
        if (![listContents isEqualToString:existingList]) {
            clean_file(listPath);
            [listContents writeToFile:@(listPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
        }
        init_file(listPath, 0, 0644);
        auto const repoPath = pathForResource(@"apt");
        _assert(repoPath != nil, message, true);
        ensure_directory("/var/lib/undecimus", 0, 0755);
        ensure_symlink([repoPath UTF8String], "/var/lib/undecimus/apt");
        if (!pkgIsConfigured("apt1.4") || !aptUpdate()) {
            auto const aptNeeded = resolveDepsForPkg(@"apt1.4", false);
            _assert(aptNeeded != nil && aptNeeded.count > 0, message, true);
            auto const aptDebs = debsForPkgs(aptNeeded);
            _assert(installDebs(aptDebs, true), message, true);
            _assert(aptUpdate(), message, true);
        }
        
        // Workaround for what appears to be an apt bug
        ensure_symlink("/var/lib/undecimus/apt/./Packages", "/var/lib/apt/lists/_var_lib_undecimus_apt_._Packages");
        
        if (debsToInstall.count > 0) {
            // Install any depends we may have ignored earlier
            _assert(aptInstall(@[@"-f"]), message, true);
            debsToInstall = nil;
        }

        // Dpkg and apt both work now
        
        if (needStrap) {
            prefs->run_uicache = true;
            _assert(set_prefs(prefs), message, true);
        }
        // Now that things are running, let's install the deb for the files we just extracted
        if (needSubstrate) {
            if (pkgIsInstalled("com.ex.substitute")) {
                _assert(removePkg("com.ex.substitute", true), message, true);
            }
            _assert(aptInstall(@[@"mobilesubstrate"]), message, true);
        }
        if (!betaFirmware) {
            if (pkgIsInstalled("com.parrotgeek.nobetaalert")) {
                _assert(removePkg("com.parrotgeek.nobetaalert", true), message, true);
            }
        }
        if (!(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0)) {
            if (pkgIsInstalled("com.ps.letmeblock")) {
                _assert(removePkg("com.ps.letmeblock", true), message, true);
            }
        }
        
        auto const file_data = [[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:@"/.installed_unc0ver"] isEqual:file_data]) {
            _assert(clean_file("/.installed_unc0ver"), message, true);
            _assert(create_file_data("/.installed_unc0ver", 0, 0644, file_data), message, true);
        }
        
        // Make sure everything's at least as new as what we bundled
        rv = system("dpkg --configure -a");
        _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
        _assert(aptUpgrade(), message, true);
        
        clean_file("/jb/tar");
        clean_file("/jb/lzma");
        clean_file("/jb/substrate.tar.lzma");
        clean_file("/electra");
        clean_file("/chimera");
        clean_file("/.bootstrapped_electra");
        clean_file([NSString stringWithFormat:@"/etc/.installed-chimera-%@", getUDID()].UTF8String);
        clean_file("/usr/lib/libjailbreak.dylib");

        LOG("Successfully extracted bootstrap.");
        
        INSERTSTATUS(NSLocalizedString(@"Extracted Bootstrap.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Disable stashing.
        
        PROGRESS(NSLocalizedString(@"Disabling stashing...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to disable stashing.", nil));
        _assert(ensure_file("/.cydia_no_stash", 0, 0644), message, true);
        LOG("Successfully disabled stashing.");
        INSERTSTATUS(NSLocalizedString(@"Disabled Stashing.\n", nil));
    }
    
    UPSTAGE();
    
    {
        // Fix storage preferences.
        
        PROGRESS(NSLocalizedString(@"Fixing storage preferences...", nil));
        SETMESSAGE(NSLocalizedString(@"Failed to fix storage preferences.", nil));
        if (access("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", "/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated") == ERR_SUCCESS, message, false);
        }
        if (access("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", "/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd") == ERR_SUCCESS, message, false);
        }
        if (access("/System/Library/com.apple.mobile.softwareupdated.plist", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/com.apple.mobile.softwareupdated.plist", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist") == ERR_SUCCESS, message, false);
            _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", NULL) == ERR_SUCCESS, message, false);
        }
        if (access("/System/Library/com.apple.softwareupdateservicesd.plist", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/com.apple.softwareupdateservicesd.plist", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist") == ERR_SUCCESS, message, false);
            _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", NULL) == ERR_SUCCESS, message, false);
        }
        LOG("Successfully fixed storage preferences.");
        INSERTSTATUS(NSLocalizedString(@"Fixed Storage Preferences.\n", nil));
    }
    
    UPSTAGE();
    
    {
        auto targettype = sysctlWithName("hw.targettype");
        _assert(targettype != NULL, message, true);
        auto const jetsamFile = [NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", targettype];
        SafeFreeNULL(targettype);
        
        if (prefs->increase_memory_limit) {
            // Increase memory limit.
            
            PROGRESS(NSLocalizedString(@"Increasing memory limit...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to increase memory limit.", nil));
            _assert(modifyPlist(jetsamFile, ^(id plist) {
                plist[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = [NSNumber numberWithInteger:[plist[@"Version4"][@"PListDevice"][@"MemoryCapacity"] integerValue]];
            }), message, true);
            LOG("Successfully increased memory limit.");
            INSERTSTATUS(NSLocalizedString(@"Increased Memory Limit.\n", nil));
        } else {
            // Restore memory limit.
            
            PROGRESS(NSLocalizedString(@"Restoring memory limit...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to restore memory limit.", nil));
            _assert(modifyPlist(jetsamFile, ^(id plist) {
                plist[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = nil;
            }), message, true);
            LOG("Successfully restored memory limit.");
            INSERTSTATUS(NSLocalizedString(@"Restored Memory Limit.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs->install_openssh) {
            // Install OpenSSH.
            PROGRESS(NSLocalizedString(@"Installing OpenSSH...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to install OpenSSH.", nil));
            _assert(aptInstall(@[@"openssh"]), message, true);
            prefs->install_openssh = false;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully installed OpenSSH.");
            
            INSERTSTATUS(NSLocalizedString(@"Installed OpenSSH.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (pkgIsInstalled("cydia-gui")) {
            // Remove Electra's Cydia.
            PROGRESS(NSLocalizedString(@"Removing Electra's Cydia...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to remove Electra's Cydia.", nil));
            _assert(removePkg("cydia-gui", true), message, true);
            prefs->install_cydia = true;
            prefs->run_uicache = true;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully removed Electra's Cydia.");
            
            INSERTSTATUS(NSLocalizedString(@"Removed Electra's Cydia.\n", nil));
        }
        if (access("/etc/apt/sources.list.d/sileo.sources", F_OK) == ERR_SUCCESS) {
            // Remove Electra's Sileo - it has trigger loops and incompatible depends
            PROGRESS(NSLocalizedString(@"Removing Incompatible Sileo...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to remove incompatible Sileo.", nil));

            if (pkgIsInstalled("org.coolstar.sileo")) {
                _assert(removePkg("org.coolstar.sileo", true), message, true);
                prefs->run_uicache = true;
                _assert(set_prefs(prefs), message, true);
            }
            clean_file("/etc/apt/sources.list.d/sileo.sources");
            
            INSERTSTATUS(NSLocalizedString(@"Removing Incompatible Sileo.\n", nil));
        }
        if (pkgIsInstalled("cydia-upgrade-helper")) {
            // Remove Electra's Cydia Upgrade Helper.
            PROGRESS(NSLocalizedString(@"Removing Electra's Cydia Upgrade Helper...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to remove Electra's Cydia Upgrade Helper.", nil));
            _assert(removePkg("cydia-upgrade-helper", true), message, true);
            prefs->install_cydia = true;
            prefs->run_uicache = true;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully removed Electra's Cydia Upgrade Helper.");
        }
        if (access("/etc/apt/sources.list.d/electra.list", F_OK) == ERR_SUCCESS ||
            access("/etc/apt/sources.list.d/chimera.sources", F_OK) == ERR_SUCCESS) {
            prefs->install_cydia = true;
            prefs->run_uicache = true;
            _assert(set_prefs(prefs), message, true);
        }
        // Unblock Saurik's repo if it is blocked.
        unblockDomainWithName("apt.saurik.com");
        if (prefs->install_cydia) {
            // Install Cydia.
            
            PROGRESS(NSLocalizedString(@"Installing Cydia...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to install Cydia.", nil));
            auto const cydiaVer = versionOfPkg(@"cydia");
            _assert(cydiaVer != nil, message, true);
            _assert(aptInstall(@[@"--reinstall", [@"cydia" stringByAppendingFormat:@"=%@", cydiaVer]]), message, true);
            prefs->install_cydia = false;
            prefs->run_uicache = true;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully installed Cydia.");
            
            INSERTSTATUS(NSLocalizedString(@"Installed Cydia.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs->load_daemons) {
            // Load Daemons.
            
            PROGRESS(NSLocalizedString(@"Loading Daemons...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to load Daemons.", nil));
            system("echo 'really jailbroken';"
                    "shopt -s nullglob;"
                    "for a in /Library/LaunchDaemons/*.plist;"
                        "do echo loading $a;"
                        "launchctl load \"$a\" ;"
                    "done; ");
            // Substrate is already running, no need to run it again
            system("for file in /etc/rc.d/*; do "
                        "if [[ -x \"$file\" && \"$file\" != \"/etc/rc.d/substrate\" ]]; then "
                            "\"$file\";"
                         "fi;"
                    "done");
            LOG("Successfully loaded Daemons.");
            
            INSERTSTATUS(NSLocalizedString(@"Loaded Daemons.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs->reset_cydia_cache) {
            // Reset Cydia cache.
            
            PROGRESS(NSLocalizedString(@"Resetting Cydia cache...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to reset Cydia cache.", nil));
            _assert(clean_file("/var/mobile/Library/Cydia"), message, true);
            _assert(clean_file("/var/mobile/Library/Caches/com.saurik.Cydia"), message, true);
            prefs->reset_cydia_cache = false;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully reset Cydia cache.");
            
            INSERTSTATUS(NSLocalizedString(@"Reset Cydia Cache.\n", nil));
        }
    }

    UPSTAGE();
    
    {
        if (prefs->run_uicache || !canOpen("cydia://")) {
            // Run uicache.
            
            PROGRESS(NSLocalizedString(@"Refreshing icon cache...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to run uicache.", nil));
            _assert(runCommand("/usr/bin/uicache", NULL) == ERR_SUCCESS, message, true);
            prefs->run_uicache = false;
            _assert(set_prefs(prefs), message, true);
            LOG("Successfully ran uicache.");
            INSERTSTATUS(NSLocalizedString(@"Ran uicache.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (!(prefs->load_tweaks && prefs->reload_system_daemons)) {
            // Flush preference cache.
            
            PROGRESS(NSLocalizedString(@"Flushing preference cache...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to flush preference cache.", nil));
            _assert(runCommand("/bin/launchctl", "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, message, true);
            LOG("Successfully flushed preference cache.");
            INSERTSTATUS(NSLocalizedString(@"Flushed preference cache.\n", nil));
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs->load_tweaks) {
            // Load Tweaks.
            
            PROGRESS(NSLocalizedString(@"Loading Tweaks...", nil));
            SETMESSAGE(NSLocalizedString(@"Failed to load tweaks.", nil));
            if (prefs->reload_system_daemons) {
                rv = system("nohup bash -c \""
                             "sleep 1 ;"
                             "launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist && "
                             "ldrestart ;"
                             "launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist"
                             "\" >/dev/null 2>&1 &");
            } else {
                rv = system("nohup bash -c \""
                             "sleep 1 ;"
                             "launchctl stop com.apple.mDNSResponder ;"
                             "launchctl stop com.apple.backboardd"
                             "\" >/dev/null 2>&1 &");
            }
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            LOG("Successfully loaded Tweaks.");
            
            INSERTSTATUS(NSLocalizedString(@"Loaded Tweaks.\n", nil));
        }
    }
out:
    PROGRESS(NSLocalizedString(@"Deinitializing jailbreak...", nil));
    LOG("Deinitializing kexecute...");
    term_kexecute();
    LOG("Unplatformizing...");
    _assert(set_platform_binary(myProcAddr, false), message, true);
    _assert(set_cs_platform_binary(myProcAddr, false), message, true);
    LOG("Sandboxing...");
    myCredAddr = myOriginalCredAddr;
    _assert(give_creds_to_process_at_addr(myProcAddr, myCredAddr) == kernelCredAddr, message, true);
    LOG("Downgrading host port...");
    _assert(setuid(myUid) == ERR_SUCCESS, message, true);
    _assert(getuid() == myUid, message, true);
    LOG("Restoring shenanigans pointer...");
    _assert(WriteKernel64(GETOFFSET(shenanigans), Shenanigans), message, true);
    LOG("Deallocating ports...");
    _assert(mach_port_deallocate(mach_task_self(), myHost) == KERN_SUCCESS, message, true);
    myHost = HOST_NULL;
    _assert(mach_port_deallocate(mach_task_self(), myOriginalHost) == KERN_SUCCESS, message, true);
    myOriginalHost = HOST_NULL;
#undef PROGRESS
    removeProgressHUD(hud);
    INSERTSTATUS(([NSString stringWithFormat:@"\nRead %zu bytes from kernel memory\nWrote %zu bytes to kernel memory\n", kreads, kwrites]));
    INSERTSTATUS(([NSString stringWithFormat:@"\nJailbroke in %ld seconds\n", time(NULL) - start_time]));
    STATUS(NSLocalizedString(@"Jailbroken", nil), false, false);
    showAlert(@"Jailbreak Completed", [NSString stringWithFormat:@"%@\n\n%@\n%@", NSLocalizedString(@"Jailbreak Completed with Status:", nil), status, NSLocalizedString((prefs->exploit == mach_swap_exploit || prefs->exploit == mach_swap_2_exploit) && !usedPersistedKernelTaskPort ? @"The device will now respring." : @"The app will now exit.", nil)], true, false);
    if (sharedController.canExit) {
        if ((prefs->exploit == mach_swap_exploit || prefs->exploit == mach_swap_2_exploit) && !usedPersistedKernelTaskPort) {
            WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL), ReadKernel64(kernelCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)));
            WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), 0);
            release_prefs(&prefs);
            _assert(restartSpringBoard(), message, true);
        } else {
            release_prefs(&prefs);
            exit(EXIT_SUCCESS);
            _assert(false, message, true);
        }
    }
    sharedController.canExit = YES;
    release_prefs(&prefs);
#undef INSERTSTATUS
}

- (IBAction)tappedOnJailbreak:(id)sender
{
    STATUS(NSLocalizedString(@"Jailbreak", nil), false, false);
    auto const block = ^(void) {
        _assert(bundledResources != nil, NSLocalizedString(@"Bundled Resources version missing.", nil), true);
        if (!jailbreakSupported()) {
            STATUS(NSLocalizedString(@"Unsupported", nil), false, true);
            return;
        }
        jailbreak();
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    auto prefs = copy_prefs();
    if (!jailbreakSupported()) {
        STATUS(NSLocalizedString(@"Unsupported", nil), false, true);
    } else if (prefs->restore_rootfs) {
        STATUS(NSLocalizedString(@"Restore RootFS", nil), true, true);
    } else if (jailbreakEnabled()) {
        STATUS(NSLocalizedString(@"Re-Jailbreak", nil), true, true);
    } else {
        STATUS(NSLocalizedString(@"Jailbreak", nil), true, true);
    }
    release_prefs(&prefs);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    _canExit = YES;
    // Do any additional setup after loading the view, typically from a nib.
    auto prefs = copy_prefs();
    if (prefs->hide_log_window) {
        _outputView.hidden = YES;
        _outputView = nil;
        _goButtonSpacing.constant += 80;
    }
    release_prefs(&prefs);
    sharedController = self;
    bundledResources = bundledResourcesVersion();
    LOG("unc0ver Version: %@", appVersion());
    printOSDetails();
    LOG("Bundled Resources Version: %@", bundledResources);
    if (bundledResources == nil) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
            showAlert(NSLocalizedString(@"Error", nil), NSLocalizedString(@"Bundled Resources version is missing. This build is invalid.", nil), false, false);
        });
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleDefault;
}

- (IBAction)tappedOnPwn:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnDennis:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"DennisBednarz"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamB:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"sbingner"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamG:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://reddit.com/u/Samg_is_a_Ninja"] options:@{} completionHandler:nil];
}

// This intentionally returns nil if called before it's been created by a proper init
+(JailbreakViewController *)sharedController {
    return sharedController;
}

-(void)updateOutputView {
    [self updateOutputViewFromQueue:@NO];
}

-(void)updateOutputViewFromQueue:(NSNumber*)fromQueue {
    static BOOL updateQueued = NO;
    static struct timeval last = {0,0};
    static dispatch_queue_t updateQueue;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        updateQueue = dispatch_queue_create("updateView", NULL);
    });
    
    dispatch_async(updateQueue, ^{
        struct timeval now;

        if (fromQueue.boolValue) {
            updateQueued = NO;
        }
        
        if (updateQueued) {
            return;
        }
        
        if (gettimeofday(&now, NULL)) {
            LOG("gettimeofday failed");
            return;
        }
        
        uint64_t elapsed = (now.tv_sec - last.tv_sec) * 1000000 + now.tv_usec - last.tv_usec;
        // 30 FPS
        if (elapsed > 1000000/30) {
            updateQueued = NO;
            gettimeofday(&last, NULL);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.outputView.text = output;
                [self.outputView scrollRangeToVisible:NSMakeRange(self.outputView.text.length, 0)];
            });
        } else {
            NSTimeInterval waitTime = ((1000000/30) - elapsed) / 1000000.0;
            updateQueued = YES;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self performSelector:@selector(updateOutputViewFromQueue:) withObject:@YES afterDelay:waitTime];
            });
        }
    });
}

-(void)appendTextToOutput:(NSString *)text {
    if (_outputView == nil) {
        return;
    }
    static NSRegularExpression *remove = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        remove = [NSRegularExpression regularExpressionWithPattern:@"^\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\.\\d+[-\\d\\s]+\\S+\\[\\d+:\\d+\\]\\s+"
                                                           options:NSRegularExpressionAnchorsMatchLines error:nil];
        output = [NSMutableString new];
    });
    
    text = [remove stringByReplacingMatchesInString:text options:0 range:NSMakeRange(0, text.length) withTemplate:@""];

    @synchronized (output) {
        [output appendString:text];
    }
    [self updateOutputView];
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithCoder:aDecoder];
        }
    }
    self = sharedController;
    return self;
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
        }
    }
    self = sharedController;
    return self;
}

- (id)init {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super init];
        }
    }
    self = sharedController;
    return self;
}

@end

// Don't move this - it is at the bottom so that it will list the total number of upstages
int maxStage = __COUNTER__ - 1;
