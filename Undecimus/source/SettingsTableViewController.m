//
//  SettingsTableViewController.m
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#include <sys/utsname.h>
#include <sys/sysctl.h>
#import "SettingsTableViewController.h"
#include <common.h>
#include "hideventsystem.h"
#include "remote_call.h"
#include "JailbreakViewController.h"
#include "utils.h"
#include "voucher_swap-poc.h"
#include "necp.h"
#include "kalloc_crash.h"
#include "prefs.h"

@interface SettingsTableViewController ()

@end

@implementation SettingsTableViewController

// https://github.com/Matchstic/ReProvision/blob/7b595c699335940f68702bb204c5aa55b8b1896f/Shared/Application%20Database/RPVApplication.m#L102

+ (NSDictionary *)_provisioningProfileAtPath:(NSString *)path {
    NSError *err;
    NSString *stringContent = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:&err];
    stringContent = [stringContent componentsSeparatedByString:@"<plist version=\"1.0\">"][1];
    stringContent = [NSString stringWithFormat:@"%@%@", @"<plist version=\"1.0\">", stringContent];
    stringContent = [stringContent componentsSeparatedByString:@"</plist>"][0];
    stringContent = [NSString stringWithFormat:@"%@%@", stringContent, @"</plist>"];
    
    NSData *stringData = [stringContent dataUsingEncoding:NSASCIIStringEncoding];
    
    NSError *error;
    NSPropertyListFormat format;
    
    id plist = [NSPropertyListSerialization propertyListWithData:stringData options:NSPropertyListImmutable format:&format error:&error];
    
    return plist;
}

#define STATUS_FILE          @"/var/lib/dpkg/status"
#define CYDIA_LIST @"/etc/apt/sources.list.d/cydia.list"

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L1138

+ (NSArray *)dependencyArrayFromString:(NSString *)depends
{
    NSMutableArray *cleanArray = [[NSMutableArray alloc] init];
    NSArray *dependsArray = [depends componentsSeparatedByString:@","];
    for (id depend in dependsArray)
    {
        NSArray *spaceDelimitedArray = [depend componentsSeparatedByString:@" "];
        NSString *isolatedDependency = [[spaceDelimitedArray objectAtIndex:0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([isolatedDependency length] == 0)
            isolatedDependency = [[spaceDelimitedArray objectAtIndex:1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        [cleanArray addObject:isolatedDependency];
    }
    
    return cleanArray;
}

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L1163

+ (NSArray *)parsedPackageArray
{
    NSString *packageString = [NSString stringWithContentsOfFile:STATUS_FILE encoding:NSUTF8StringEncoding error:nil];
    NSArray *lineArray = [packageString componentsSeparatedByString:@"\n\n"];
    //NSLog(@"lineArray: %@", lineArray);
    NSMutableArray *mutableList = [[NSMutableArray alloc] init];
    //NSMutableDictionary *mutableDict = [[NSMutableDictionary alloc] init];
    for (id currentItem in lineArray)
    {
        NSArray *packageArray = [currentItem componentsSeparatedByString:@"\n"];
        //    NSLog(@"packageArray: %@", packageArray);
        NSMutableDictionary *currentPackage = [[NSMutableDictionary alloc] init];
        for (id currentLine in packageArray)
        {
            NSArray *itemArray = [currentLine componentsSeparatedByString:@": "];
            if ([itemArray count] >= 2)
            {
                NSString *key = [itemArray objectAtIndex:0];
                NSString *object = [itemArray objectAtIndex:1];
                
                if ([key isEqualToString:@"Depends"]) //process the array
                {
                    NSArray *dependsObject = [SettingsTableViewController dependencyArrayFromString:object];
                    
                    [currentPackage setObject:dependsObject forKey:key];
                    
                } else { //every other key, even if it has an array is treated as a string
                    
                    [currentPackage setObject:object forKey:key];
                }
                
                
            }
        }
        
        //NSLog(@"currentPackage: %@\n\n", currentPackage);
        if ([[currentPackage allKeys] count] > 4)
        {
            //[mutableDict setObject:currentPackage forKey:[currentPackage objectForKey:@"Package"]];
            [mutableList addObject:currentPackage];
        }
        
        currentPackage = nil;
        
    }
    
    NSSortDescriptor *nameDescriptor = [[NSSortDescriptor alloc] initWithKey:@"Name" ascending:YES
                                                                    selector:@selector(localizedCaseInsensitiveCompare:)];
    NSSortDescriptor *packageDescriptor = [[NSSortDescriptor alloc] initWithKey:@"Package" ascending:YES
                                                                       selector:@selector(localizedCaseInsensitiveCompare:)];
    NSArray *descriptors = [NSArray arrayWithObjects:nameDescriptor, packageDescriptor, nil];
    NSArray *sortedArray = [mutableList sortedArrayUsingDescriptors:descriptors];
    
    mutableList = nil;
    
    return sortedArray;
}

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L854

+ (NSString *)domainFromRepoObject:(NSString *)repoObject
{
    //LogSelf;
    if ([repoObject length] == 0)return nil;
    NSArray *sourceObjectArray = [repoObject componentsSeparatedByString:@" "];
    NSString *url = [sourceObjectArray objectAtIndex:1];
    if ([url length] > 7)
    {
        NSString *urlClean = [url substringFromIndex:7];
        NSArray *secondArray = [urlClean componentsSeparatedByString:@"/"];
        return [secondArray objectAtIndex:0];
    }
    return nil;
}

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L869

+ (NSArray *)sourcesFromFile:(NSString *)theSourceFile
{
    NSMutableArray *finalArray = [[NSMutableArray alloc] init];
    NSString *sourceString = [[NSString stringWithContentsOfFile:theSourceFile encoding:NSASCIIStringEncoding error:nil] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSArray *sourceFullArray =  [sourceString componentsSeparatedByString:@"\n"];
    NSEnumerator *sourceEnum = [sourceFullArray objectEnumerator];
    id currentSource = nil;
    while (currentSource = [sourceEnum nextObject])
    {
        NSString *theObject = [SettingsTableViewController domainFromRepoObject:currentSource];
        if (theObject != nil)
        {
            if (![finalArray containsObject:theObject])
                [finalArray addObject:theObject];
        }
    }
    
    return finalArray;
}

+ (NSDictionary *)getDiagnostics {
    struct utsname u = { 0 };
    uname(&u);
    NSDictionary *systemVersion = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    NSDictionary *diagnostics = @{
        @"Sysname": @(u.sysname),
        @"Nodename": @(u.nodename),
        @"Release": @(u.release),
        @"Version": @(u.version),
        @"Machine": @(u.machine),
        @"ProductVersion": systemVersion[@"ProductVersion"],
        @"ProductBuildVersion": systemVersion[@"ProductBuildVersion"],
        @"Sources": [SettingsTableViewController sourcesFromFile:CYDIA_LIST],
        @"Packages": [SettingsTableViewController parsedPackageArray],
        @"Preferences": @{
            @K_TWEAK_INJECTION: [NSNumber numberWithBool:(BOOL)prefs->load_tweaks],
            @K_LOAD_DAEMONS: [NSNumber numberWithBool:(BOOL)prefs->load_daemons],
            @K_DUMP_APTICKET: [NSNumber numberWithBool:(BOOL)prefs->dump_apticket],
            @K_REFRESH_ICON_CACHE: [NSNumber numberWithBool:(BOOL)prefs->run_uicache],
            @K_BOOT_NONCE: [NSString stringWithUTF8String:(const char *)prefs->boot_nonce],
            @K_DISABLE_AUTO_UPDATES: [NSNumber numberWithBool:(BOOL)prefs->disable_auto_updates],
            @K_DISABLE_APP_REVOKES: [NSNumber numberWithBool:(BOOL)prefs->disable_app_revokes],
            @K_OVERWRITE_BOOT_NONCE: [NSNumber numberWithBool:(BOOL)prefs->overwrite_boot_nonce],
            @K_EXPORT_KERNEL_TASK_PORT: [NSNumber numberWithBool:(BOOL)prefs->export_kernel_task_port],
            @K_RESTORE_ROOTFS: [NSNumber numberWithBool:(BOOL)prefs->restore_rootfs],
            @K_INCREASE_MEMORY_LIMIT: [NSNumber numberWithBool:(BOOL)prefs->increase_memory_limit],
            @K_ECID: [NSString stringWithUTF8String:(const char *)prefs->ecid],
            @K_INSTALL_CYDIA: [NSNumber numberWithBool:(BOOL)prefs->install_cydia],
            @K_INSTALL_OPENSSH: [NSNumber numberWithBool:(BOOL)prefs->install_openssh],
            @K_RELOAD_SYSTEM_DAEMONS: [NSNumber numberWithBool:(BOOL)prefs->reload_system_daemons],
            @K_RESET_CYDIA_CACHE: [NSNumber numberWithBool:(BOOL)prefs->reset_cydia_cache],
            @K_SSH_ONLY: [NSNumber numberWithBool:(BOOL)prefs->ssh_only],
            @K_ENABLE_GET_TASK_ALLOW: [NSNumber numberWithBool:(BOOL)prefs->enable_get_task_allow],
            @K_SET_CS_DEBUGGED: [NSNumber numberWithBool:(BOOL)prefs->set_cs_debugged],
            @K_HIDE_LOG_WINDOW: [NSNumber numberWithBool:(BOOL)prefs->hide_log_window],
            @K_EXPLOIT: [NSNumber numberWithInt:(int)prefs->exploit]
        },
        @"AppVersion": appVersion(),
        @"LogFile": [NSString stringWithContentsOfFile:getLogFile() encoding:NSUTF8StringEncoding error:nil]
    };
    release_prefs(&prefs);
    return diagnostics;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadData];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    UIImageView *myImageView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"Clouds"]];
    [myImageView setContentMode:UIViewContentModeScaleAspectFill];
    [myImageView setFrame:self.tableView.frame];
    UIView *myView = [[UIView alloc] initWithFrame:myImageView.frame];
    [myView setBackgroundColor:[UIColor whiteColor]];
    [myView setAlpha:0.84];
    [myView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [myImageView addSubview:myView];
    [self.tableView setBackgroundView:myImageView];
    [self.BootNonceTextField setDelegate:self];
    self.tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    self.tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:self.tap];
}

- (void)userTappedAnyware:(UITapGestureRecognizer *) sender
{
    [self.view endEditing:YES];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)reloadData {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    [self.TweakInjectionSwitch setOn:(BOOL)prefs->load_tweaks];
    [self.LoadDaemonsSwitch setOn:(BOOL)prefs->load_daemons];
    [self.DumpAPTicketSwitch setOn:(BOOL)prefs->dump_apticket];
    [self.BootNonceTextField setPlaceholder:@(prefs->boot_nonce)];
    [self.BootNonceTextField setText:nil];
    [self.RefreshIconCacheSwitch setOn:(BOOL)prefs->run_uicache];
    [self.KernelExploitSegmentedControl setSelectedSegmentIndex:(int)prefs->exploit];
    [self.DisableAutoUpdatesSwitch setOn:(BOOL)prefs->disable_auto_updates];
    [self.DisableAppRevokesSwitch setOn:(BOOL)prefs->disable_app_revokes];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(empty_list_exploit) forSegmentAtIndex:empty_list_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(multi_path_exploit) forSegmentAtIndex:multi_path_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(async_wake_exploit) forSegmentAtIndex:async_wake_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(voucher_swap_exploit) forSegmentAtIndex:voucher_swap_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(mach_swap_exploit) forSegmentAtIndex:mach_swap_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(mach_swap_2_exploit) forSegmentAtIndex:mach_swap_2_exploit];
    [self.OpenCydiaButton setEnabled:[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]];
    [self.ExpiryLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)[[SettingsTableViewController _provisioningProfileAtPath:[[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]][@"ExpirationDate"] timeIntervalSinceDate:[NSDate date]] / 86400, NSLocalizedString(@"Days", nil)]];
    [self.OverwriteBootNonceSwitch setOn:(BOOL)prefs->overwrite_boot_nonce];
    [self.ExportKernelTaskPortSwitch setOn:(BOOL)prefs->export_kernel_task_port];
    [self.RestoreRootFSSwitch setOn:(BOOL)prefs->restore_rootfs];
    [self.UptimeLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)uptime() / 86400, NSLocalizedString(@"Days", nil)]];
    [self.IncreaseMemoryLimitSwitch setOn:(BOOL)prefs->increase_memory_limit];
    [self.installSSHSwitch setOn:(BOOL)prefs->install_openssh];
    [self.installCydiaSwitch setOn:(BOOL)prefs->install_cydia];
    [self.ECIDLabel setPlaceholder:hexFromInt([@(prefs->ecid) integerValue])];
    [self.ReloadSystemDaemonsSwitch setOn:(BOOL)prefs->reload_system_daemons];
    [self.HideLogWindowSwitch setOn:(BOOL)prefs->hide_log_window];
    [self.ResetCydiaCacheSwitch setOn:(BOOL)prefs->reset_cydia_cache];
    [self.SSHOnlySwitch setOn:(BOOL)prefs->ssh_only];
    [self.EnableGetTaskAllowSwitch setOn:(BOOL)prefs->enable_get_task_allow];
    [self.SetCSDebuggedSwitch setOn:(BOOL)prefs->set_cs_debugged];
    [self.RestartSpringBoardButton setEnabled:respringSupported()];
    [self.restartButton setEnabled:restartSupported()];
    release_prefs(&prefs);
    [self.tableView reloadData];
}

- (IBAction)TweakInjectionSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->load_tweaks = (bool)self.TweakInjectionSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)LoadDaemonsSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->load_daemons = (bool)self.LoadDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)DumpAPTicketSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->dump_apticket = (bool)self.DumpAPTicketSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)BootNonceTextFieldTriggered:(id)sender {
    uint64_t val = 0;
    if ([[NSScanner scannerWithString:[self.BootNonceTextField text]] scanHexLongLong:&val] && val != HUGE_VAL && val != -HUGE_VAL) {
        prefs_t *prefs = new_prefs();
        load_prefs(prefs);
        prefs->boot_nonce = [NSString stringWithFormat:@ADDR, val].UTF8String;
        set_prefs(prefs);
        release_prefs(&prefs);
    } else {
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Invalid Entry", nil) message:NSLocalizedString(@"The boot nonce entered could not be parsed", nil) preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *OK = [UIAlertAction actionWithTitle:NSLocalizedString(@"OK", nil) style:UIAlertActionStyleDefault handler:nil];
        [alertController addAction:OK];
        [self presentViewController:alertController animated:YES completion:nil];
    }
    [self reloadData];
}

- (IBAction)RefreshIconCacheSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->run_uicache = (bool)self.RefreshIconCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)KernelExploitSegmentedControl:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->exploit = (int)self.KernelExploitSegmentedControl.selectedSegmentIndex;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)DisableAppRevokesSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->disable_app_revokes = (bool)self.DisableAppRevokesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnRestart:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        NOTICE(NSLocalizedString(@"The device will be restarted.", nil), true, false);
        NSInteger support = recommendedRestartSupport();
        _assert(support != -1, message, true);
        switch (support) {
            case necp_exploit: {
                necp_die();
                break;
            }
            case voucher_swap_exploit: {
                voucher_swap_poc();
                break;
            }
            case kalloc_crash: {
                do_kalloc_crash();
                break;
            }
            default:
                break;
        }
        exit(EXIT_FAILURE);
    });
}

- (IBAction)DisableAutoUpdatesSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->disable_auto_updates = (bool)self.DisableAutoUpdatesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnShareDiagnosticsData:(id)sender {
    NSURL *URL = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/Documents/diagnostics.plist", NSHomeDirectory()]];
    [[SettingsTableViewController getDiagnostics] writeToURL:URL error:nil];
    UIActivityViewController *activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[URL] applicationActivities:nil];
    if ([activityViewController respondsToSelector:@selector(popoverPresentationController)]) {
        [[activityViewController popoverPresentationController] setSourceView:self.ShareDiagnosticsDataButton];
    }
    [self presentViewController:activityViewController animated:YES completion:nil];
}

- (IBAction)tappedOnOpenCydia:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"cydia://"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnOpenGithub:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus"] options:@{} completionHandler:nil];
}

- (IBAction)OverwriteBootNonceSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->overwrite_boot_nonce = (bool)self.OverwriteBootNonceSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnCopyNonce:(id)sender{
    UIAlertController *copyBootNonceAlert = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Copy boot nonce?", nil) message:NSLocalizedString(@"Would you like to copy nonce generator to clipboard?", nil) preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *copyAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Yes", nil) style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        prefs_t *prefs = new_prefs();
        load_prefs(prefs);
        [[UIPasteboard generalPasteboard] setString:@(prefs->boot_nonce)];
        release_prefs(&prefs);
    }];
    UIAlertAction *noAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"No", nil) style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCopyECID:(id)sender {
    UIAlertController *copyBootNonceAlert = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Copy ECID?", nil) message:NSLocalizedString(@"Would you like to ECID to clipboard?", nil) preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *copyAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Yes", nil) style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        prefs_t *prefs = new_prefs();
        load_prefs(prefs);
        [[UIPasteboard generalPasteboard] setString:hexFromInt(@(prefs->ecid).integerValue)];
        release_prefs(&prefs);
    }];
    UIAlertAction *noAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"No", nil) style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCheckForUpdate:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        NSString *Update = [NSString stringWithContentsOfURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus/raw/master/Update.txt"] encoding:NSUTF8StringEncoding error:nil];
        if (Update == nil) {
            NOTICE(NSLocalizedString(@"Failed to check for update.", nil), true, false);
        } else if ([Update compare:appVersion() options:NSNumericSearch] == NSOrderedDescending) {
            NOTICE(NSLocalizedString(@"An update is available.", nil), true, false);
        } else {
            NOTICE(NSLocalizedString(@"Already up to date.", nil), true, false);
        }
    });
}

- (IBAction)exportKernelTaskPortSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->export_kernel_task_port = (bool)self.ExportKernelTaskPortSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)RestoreRootFSSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->restore_rootfs = (bool)self.RestoreRootFSSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installCydiaSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->install_cydia = (bool)self.installCydiaSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installSSHSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->install_openssh = (bool)self.installSSHSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (void)tableView:(UITableView *)tableView willDisplayFooterView:(UITableViewHeaderFooterView *)footerView forSection:(NSInteger)section {
    footerView.textLabel.text = [@"unc0ver " stringByAppendingString:appVersion()];
    footerView.textLabel.textAlignment = NSTextAlignmentCenter;
}

- (IBAction)IncreaseMemoryLimitSwitch:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->increase_memory_limit = (bool)self.IncreaseMemoryLimitSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnAutomaticallySelectExploit:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->exploit = (int)recommendedJailbreakSupport();
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)reloadSystemDaemonsSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->reload_system_daemons = (bool)self.ReloadSystemDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedRestartSpringBoard:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        SETMESSAGE(NSLocalizedString(@"Failed to restart SpringBoard.", nil));
        NOTICE(NSLocalizedString(@"SpringBoard will be restarted.", nil), true, false);
        NSInteger support = recommendedRespringSupport();
        _assert(support != -1, message, true);
        switch (support) {
            case deja_xnu_exploit: {
                mach_port_t bb_tp = hid_event_queue_exploit();
                _assert(MACH_PORT_VALID(bb_tp), message, true);
                _assert(thread_call_remote(bb_tp, exit, 1, REMOTE_LITERAL(EXIT_SUCCESS)) == ERR_SUCCESS, message, true);
                break;
            }
            default:
                break;
        }
        exit(EXIT_FAILURE);
    });
}

- (IBAction)tappedOnCleanDiagnosticsData:(id)sender {
    cleanLogs();
    NOTICE(NSLocalizedString(@"Cleaned diagnostics data.", nil), false, false);
}

- (IBAction)hideLogWindowSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->hide_log_window = (bool)self.HideLogWindowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        NOTICE(NSLocalizedString(@"Preference was changed. The app will now exit.", nil), true, false);
        exit(EXIT_SUCCESS);
    });
}

- (IBAction)resetCydiaCacheSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->reset_cydia_cache = (bool)self.ResetCydiaCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)sshOnlySwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->ssh_only = (bool)self.SSHOnlySwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)enableGetTaskAllowSwitchTriggered:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->enable_get_task_allow = (bool)self.EnableGetTaskAllowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)setCSDebugged:(id)sender {
    prefs_t *prefs = new_prefs();
    load_prefs(prefs);
    prefs->set_cs_debugged = (bool)self.SetCSDebuggedSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnResetAppPreferences:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        reset_prefs();
        NOTICE(NSLocalizedString(@"Preferences were reset. The app will now exit.", nil), true, false);
        exit(EXIT_SUCCESS);
    });
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
