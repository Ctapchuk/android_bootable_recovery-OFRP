/*
	Copyright 2012-2020 TeamWin
	This file is part of TWRP/TeamWin Recovery Project.

	Copyright (C) 2018-2023 OrangeFox Recovery Project
	This file is part of the OrangeFox Recovery Project.

	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include "recovery_utils/battery_utils.h"
#include "gui/twmsg.h"
#include "cutils/properties.h"

#ifdef ANDROID_RB_RESTART
#include "cutils/android_reboot.h"
#else
#include <sys/reboot.h>
#endif

extern "C" {
#include "gui/gui.h"
}
#include "set_metadata.h"
#include "gui/gui.hpp"
#include "gui/pages.hpp"
#include "gui/objects.hpp"
#include "twcommon.h"
#include "twrp-functions.hpp"
#include "data.hpp"

#include "partitions.hpp"
#ifdef __ANDROID_API_N__
#include <android-base/strings.h>
#else
#include <base/strings.h>
#endif
#include "openrecoveryscript.hpp"
#include "variables.h"
#include "startupArgs.hpp"
#include "twrpAdbBuFifo.hpp"
#ifdef TW_USE_NEW_MINADBD
// #include "minadbd/minadbd.h"
#else
extern "C" {
#include "minadbd21/adb.h"
}
#endif

#ifdef TW_INCLUDE_CRYPTO
#include "FsCrypt.h"
#include "Decrypt.h"
#endif

//extern int adb_server_main(int is_daemon, int server_port, int /* reply_fd */);

TWPartitionManager PartitionManager;
int Log_Offset;
bool datamedia;

static void Print_Prop(const char *key, const char *name, void *cookie) {
	printf("%s=%s\n", key, name);
}

static void Decrypt_Page(bool SkipDecryption, bool datamedia) {
	// Offer to decrypt if the device is encrypted
	if (DataManager::GetIntValue(TW_IS_ENCRYPTED) != 0) {
		if (SkipDecryption) {
			LOGINFO("Skipping decryption\n");
			PartitionManager.Update_System_Details();
		} else if (DataManager::GetIntValue(TW_CRYPTO_PWTYPE) != 0) {
			DataManager::SetValue(FOX_ENCRYPTED_DEVICE, "1");
			LOGINFO("Is encrypted, do decrypt page first\n");
			if (DataManager::GetIntValue(TW_IS_FBE))
				DataManager::SetValue("tw_crypto_user_id", "0");
			if (gui_startPage("decrypt", 1, 1) != 0) {
				LOGERR("Failed to start decrypt GUI page.\n");
			} else {
				// OrangeFox - make note of this decryption
				DataManager::SetValue("OTA_decrypted", "1");
				usleep(16);
			}
		}
	} else if (datamedia) {
		PartitionManager.Update_System_Details();
		if (tw_get_default_metadata(DataManager::GetCurrentStoragePath().c_str()) != 0 && tw_get_default_metadata(DataManager::GetSettingsStoragePath().c_str()) != 0) {
			LOGINFO("Failed to get default contexts and file mode for storage files.\n");
		} else {
			LOGINFO("Got default contexts and file mode for storage files.\n");
		}
	}
}

static void process_fastbootd_mode() {
		LOGINFO("starting fastboot\n");

		if (android::base::GetBoolProperty("ro.boot.dynamic_partitions", false)) {
			PartitionManager.Unmap_Super_Devices();
		}
		
#ifdef AB_OTA_UPDATER
		DataManager::SetValue("tw_active_slot", PartitionManager.Get_Active_Slot_Display());
#endif

		gui_msg(Msg("fastboot_console_msg=Entered Fastboot mode..."));
		property_set("ro.orangefox.fastbootd", "1");
		property_set("ro.boot.verifiedbootstate", "orange");
		TWFunc::RunFoxScript("/system/bin/runatboot.sh", "");
		TWFunc::RunFoxScript("/system/bin/postfastboot.sh", "");
		if (gui_startPage("fastboot", 1, 1) != 0) {
			LOGERR("Failed to start fastbootd page.\n");
		}
		property_set("ro.orangefox.fastbootd", "0");
}

static void process_recovery_mode(twrpAdbBuFifo* adb_bu_fifo, bool skip_decryption) {
	char crash_prop_val[PROPERTY_VALUE_MAX];
	int crash_counter;

	property_get("orangefox.crash_counter", crash_prop_val, "-1");
	crash_counter = atoi(crash_prop_val) + 1;
	snprintf(crash_prop_val, sizeof(crash_prop_val), "%d", crash_counter);
	property_set("orangefox.crash_counter", crash_prop_val);

	if (crash_counter == 0) {
		property_list(Print_Prop, NULL);
		printf("\n");
	} else {
		printf("orangefox.crash_counter=%d\n", crash_counter);
	}

	// Set the props for OrangeFox dynamic partitions
	PartitionManager.Fox_Set_Dynamic_Partition_Props(); // don't move this from here!

// We are doing this here to allow super partition to be set up prior to overriding properties
#if defined(TW_INCLUDE_LIBRESETPROP)
	std::vector<std::string> build_date_props = {"ro.build.date.utc", "ro.bootimage.build.date.utc", "ro.vendor.build.date.utc", "ro.system.build.date.utc", "ro.system_ext.build.date.utc", "ro.product.build.date.utc", "ro.odm.build.date.utc"};
	std::string val = "0";
	#ifdef FOX_BUGGED_AOSP_ARB_WORKAROUND
	val = FOX_BUGGED_AOSP_ARB_WORKAROUND;
	#endif
	for (auto prop : build_date_props) {
		TWFunc::Property_Override(prop, val);
		LOGINFO("Overriding %s with value: \"%s\"\n", prop.c_str(), val.c_str());
	}
#if defined(TW_OVERRIDE_SYSTEM_PROPS)
	stringstream override_props(EXPAND(TW_OVERRIDE_SYSTEM_PROPS));
	string current_prop;

	std::vector<std::string> partition_list;
	partition_list.push_back (PartitionManager.Get_Android_Root_Path().c_str());
#ifdef TW_OVERRIDE_PROPS_ADDITIONAL_PARTITIONS
	std::vector<std::string> additional_partition_list = TWFunc::Split_String(TW_OVERRIDE_PROPS_ADDITIONAL_PARTITIONS, " ");
	partition_list.insert(partition_list.end(), additional_partition_list.begin(), additional_partition_list.end());
#endif
	std::vector<std::string> build_prop_list = {"build.prop"};
#ifdef TW_SYSTEM_BUILD_PROP_ADDITIONAL_PATHS
	std::vector<std::string> additional_build_prop_list = TWFunc::Split_String(TW_SYSTEM_BUILD_PROP_ADDITIONAL_PATHS, ";");
	build_prop_list.insert(build_prop_list.end(), additional_build_prop_list.begin(), additional_build_prop_list.end());
#endif
	while (getline(override_props, current_prop, ';')) {
		string other_prop;
		if (current_prop.find("=") != string::npos) {
			other_prop = current_prop.substr(current_prop.find("=") + 1);
			current_prop = current_prop.substr(0, current_prop.find("="));
		} else {
			other_prop = current_prop;
		}
		other_prop = android::base::Trim(other_prop);
		current_prop = android::base::Trim(current_prop);

		for (auto&& partition_mount_point:partition_list) {
			for (auto&& prop_file:build_prop_list) {
				string sys_val = TWFunc::Partition_Property_Get(other_prop, PartitionManager, partition_mount_point.c_str(), prop_file);
				if (!sys_val.empty()) {
					if (partition_mount_point == "/system_root") {
						LOGINFO("Overriding %s with value: \"%s\" from property %s in /system/%s\n", current_prop.c_str(), sys_val.c_str(), other_prop.c_str(),
							prop_file.c_str());
					} else {
						LOGINFO("Overriding %s with value: \"%s\" from property %s in /%s/%s\n", current_prop.c_str(), sys_val.c_str(), other_prop.c_str(),
							partition_mount_point.c_str(), prop_file.c_str());
					}
					int error = TWFunc::Property_Override(current_prop, sys_val);
					if (error) {
						LOGERR("Failed overriding property %s, error_code: %d\n", current_prop.c_str(), error);
					}
					if (partition_mount_point == partition_list.back()) {
						PartitionManager.UnMount_By_Path(partition_mount_point, false);
					}
					goto exit;
				} else {
					if (partition_mount_point == "/system_root") {
						LOGINFO("Unable to override property %s: property not found in /system/%s\n", current_prop.c_str(), prop_file.c_str());
					} else {
						LOGINFO("Unable to override property %s: property not found in /%s/%s\n", current_prop.c_str(), partition_mount_point.c_str(), prop_file.c_str());
					}
				}
			}
			PartitionManager.UnMount_By_Path(partition_mount_point, false);
		}
		exit:
		continue;
	}
#endif // defined(TW_OVERRIDE_SYSTEM_PROPS)
#endif // defined(TW_INCLUDE_LIBRESETPROP)

        // use the ROM's fingerprint?
        TWFunc::RunStartupScript();
        TWFunc::UseSystemFingerprint();
	TWFunc::RunFoxScript("/system/bin/runatboot.sh", "");

#ifdef TW_INCLUDE_INJECTTWRP
	// Back up TWRP Ramdisk if needed:
	TWPartition* Boot = PartitionManager.Find_Partition_By_Path("/boot");
	LOGINFO("Backing up TWRP ramdisk...\n");
	if (Boot == NULL || Boot->Current_File_System != "emmc")
		TWFunc::Exec_Cmd("injecttwrp --backup /tmp/backup_recovery_ramdisk.img");
	else {
		string injectcmd = "injecttwrp --backup /tmp/backup_recovery_ramdisk.img bd=" + Boot->Actual_Block_Device;
		TWFunc::Exec_Cmd(injectcmd);
	}
	LOGINFO("Backup of OrangeFox ramdisk done.\n");
#endif

#ifdef OF_ADVANCED_SECURITY
  	property_set("ctl.stop", "adbd");
  	property_set("orangefox.adb.status", "0");
#endif

#ifdef TW_INCLUDE_CRYPTO
	android::keystore::copySqliteDb();
#endif
	Decrypt_Page(skip_decryption, datamedia);

	// Check for and load custom theme if present
	TWFunc::check_selinux_support();
	gui_loadCustomResources();
	PartitionManager.Output_Partition_Logging();

	// Fixup the RTC clock on devices which require it
	if (crash_counter == 0)
		TWFunc::Fixup_Time_On_Boot();

	TWFunc::Update_Log_File();
	DataManager::ReadSettingsFile();

	// Run any outstanding OpenRecoveryScript
	std::string cacheDir = TWFunc::get_log_dir();
	if (cacheDir == DATA_LOGS_DIR)
		cacheDir = "/data/cache";
	std::string orsFile = cacheDir + "/recovery/openrecoveryscript";
	if ((DataManager::GetIntValue(TW_IS_ENCRYPTED) == 0 || skip_decryption) && (TWFunc::Path_Exists(SCRIPT_FILE_TMP) || TWFunc::Path_Exists(orsFile))) {
		OpenRecoveryScript::Run_OpenRecoveryScript();
	}

  	// call OrangeFox startup code
  	TWFunc::OrangeFox_Startup();
  	
#ifdef OF_ADVANCED_SECURITY
	LOGINFO("ADB & MTP disabled by maintainer\n");
	DataManager::SetValue("fox_advanced_security", "1");
  	DataManager::SetValue("tw_mtp_enabled", 0);
#else
#ifdef TW_HAS_MTP
	char mtp_crash_check[PROPERTY_VALUE_MAX];
	property_get("mtp.crash_check", mtp_crash_check, "0");
	if (DataManager::GetIntValue("tw_mtp_enabled")
			&& !strcmp(mtp_crash_check, "0") && !crash_counter
			&& (!DataManager::GetIntValue(TW_IS_ENCRYPTED) || DataManager::GetIntValue(TW_IS_DECRYPTED))) {
		property_set("mtp.crash_check", "1");
		LOGINFO("Starting MTP\n");
		if (!PartitionManager.Enable_MTP())
			PartitionManager.Disable_MTP();
		else
			gui_msg("mtp_enabled=MTP Enabled");
		property_set("mtp.crash_check", "0");
	} else if (strcmp(mtp_crash_check, "0")) {
		gui_warn("mtp_crash=MTP Crashed, not starting MTP on boot.");
		DataManager::SetValue("tw_mtp_enabled", 0);
		PartitionManager.Disable_MTP();
	} else if (crash_counter == 1) {
		LOGINFO("OrangeFox crashed; disabling MTP as a precaution.\n");
		PartitionManager.Disable_MTP();
	}
#endif
#endif

#ifndef TW_OEM_BUILD
	// Check if system has never been changed
	TWPartition* sys = PartitionManager.Find_Partition_By_Path(PartitionManager.Get_Android_Root_Path());
	TWPartition* ven = PartitionManager.Find_Partition_By_Path("/vendor");
	if (sys) {
		if (sys->Get_Super_Status()) {
#ifdef TW_INCLUDE_CRYPTO
			std::string recoveryLogDir(DATA_LOGS_DIR);
			recoveryLogDir += "/recovery";
			if (!TWFunc::Path_Exists(recoveryLogDir)) {
				bool created = PartitionManager.Recreate_Logs_Dir();
				if (!created)
					LOGERR("Unable to create log directory for TWRP\n");
			}
			DataManager::ReadSettingsFile();
#endif
		} else {
			if ((DataManager::GetIntValue("tw_mount_system_ro") == 0 && sys->Check_Lifetime_Writes() == 0) || DataManager::GetIntValue("tw_mount_system_ro") == 2) {
				if (DataManager::GetIntValue("tw_never_show_system_ro_page") == 0) {
					DataManager::SetValue("tw_back", "main");
					if (gui_startPage("system_readonly", 1, 1) != 0) {
						LOGERR("Failed to start system_readonly GUI page.\n");
					}
				} else if (DataManager::GetIntValue("tw_mount_system_ro") == 0) {
					sys->Change_Mount_Read_Only(false);
					if (ven)
						ven->Change_Mount_Read_Only(false);
				}
			} else if (DataManager::GetIntValue("tw_mount_system_ro") == 1) {
				// Do nothing, user selected to leave system read only
			} else {
				sys->Change_Mount_Read_Only(false);
				if (ven)
					ven->Change_Mount_Read_Only(false);
			}
		}
	}
#endif

	TWFunc::Update_Log_File();

	adb_bu_fifo->threadAdbBuFifo();

	// run the postrecoveryboot script here
	TWFunc::RunFoxScript("/system/bin/postrecoveryboot.sh", "");
#ifndef OF_DEVICE_WITHOUT_PERSIST
	DataManager::RestorePasswordBackup();
#endif

#ifndef TW_OEM_BUILD
	// Disable flashing of stock recovery
	TWFunc::Disable_Stock_Recovery_Replace();
#endif

	PartitionManager.Refresh_Mounting_Info();
}

static void reboot() {
	gui_msg(Msg("rebooting=Rebooting..."));
	TWFunc::Update_Log_File();
	string Reboot_Arg;

#ifdef TW_INCLUDE_CRYPTO
//	fscrypt_lock_user_key(0);
#endif
	DataManager::GetValue("tw_reboot_arg", Reboot_Arg);
	if (Reboot_Arg == "recovery")
		TWFunc::tw_reboot(rb_recovery);
	else if (Reboot_Arg == "poweroff")
		TWFunc::tw_reboot(rb_poweroff);
	else if (Reboot_Arg == "bootloader")
		TWFunc::tw_reboot(rb_bootloader);
	else if (Reboot_Arg == "download")
		TWFunc::tw_reboot(rb_download);
	else if (Reboot_Arg == "edl")
		TWFunc::tw_reboot(rb_edl);
	else if (Reboot_Arg == "fastboot")
		TWFunc::tw_reboot(rb_fastboot);
	else
		TWFunc::tw_reboot(rb_system);
}

// check whether we should reload the themes
static bool Fox_CheckReload_Themes() {
  if (DataManager::GetStrValue("data_decrypted") == "1" 
  || DataManager::GetIntValue(TW_IS_FBE) == 1 
  || TWFunc::Fox_Property_Get("orangefox.mount_to_decrypt") == "1") {
	DataManager::SetValue(FOX_ENCRYPTED_DEVICE, "1");
    }
  return (TWFunc::Path_Exists(FOX_THEME_PATH) || TWFunc::Path_Exists(FOX_NAVBAR_PATH));
}

int main(int argc, char **argv) {
	// Recovery needs to install world-readable files, so clear umask
	// set by init
	umask(0);

	Log_Offset = 0;

	// Set up temporary log file (/tmp/recovery.log)
	freopen(TMP_LOG_FILE, "a", stdout);
	setbuf(stdout, NULL);
	freopen(TMP_LOG_FILE, "a", stderr);
	setbuf(stderr, NULL);

	signal(SIGPIPE, SIG_IGN);

	// Handle ADB sideload
	if (argc == 3 && strcmp(argv[1], "--adbd") == 0) {
		property_set("ctl.stop", "adbd");
#ifdef TW_USE_NEW_MINADBD
		//adb_server_main(0, DEFAULT_ADB_PORT, -1); TODO fix this for android8
		// minadbd_main();
#else
		adb_main(argv[2]);
#endif
		return 0;
	}

#ifdef RECOVERY_SDCARD_ON_DATA
	datamedia = true;
#endif

	// Fox stuff
	TWFunc::Set_Sbin_Dir_Executable_Flags();
  	property_set("ro.orangefox.boot", "1");
  	property_set("ro.orangefox.version", FOX_VERSION);
  	property_set("ro.orangefox.type", FOX_BUILD_TYPE);
  	property_set("ro.orangefox.variant", FOX_VARIANT);
  	property_set("ro.orangefox.build", "orangefox");
  	property_set("ro.orangefox.boot.header.version", BOARD_BOOT_HEADER_VERSION);

  	#ifdef FOX_TARGET_DEVICES
	property_set("ro.twrp.target.devices", FOX_TARGET_DEVICES);
  	#endif

	#ifdef OF_DYNAMIC_FULL_SIZE
	TWFunc::Fox_Property_Set("ro.dynamic.full_size", OF_DYNAMIC_FULL_SIZE);
	#endif

	#ifdef OF_SKIP_FBE_DECRYPTION
	TWFunc::Fox_Property_Set("of_skip_fbe_decryption", "true");
	#endif

	#ifdef OF_DEFAULT_KEYMASTER_VERSION
	android::base::SetProperty(TW_KEYMASTER_VERSION_PROP, OF_DEFAULT_KEYMASTER_VERSION);
	#endif

	#ifdef FOX_VIRTUAL_AB_DEVICE
	property_set("ro.orangefox.virtual_ab", "1");
	#endif

    	string fox_cfg = Fox_Cfg;
    	if (!TWFunc::Path_Exists(fox_cfg))
    	    fox_cfg = "/system" + Fox_Cfg;
  	string fox_build_date = TWFunc::File_Property_Get (fox_cfg, "FOX_BUILD_DATE");
  	if (fox_build_date == "") {
        	fox_build_date = TWFunc::File_Property_Get ("/default.prop", "ro.bootimage.build.date");
        	if (fox_build_date == "") {
              		fox_build_date = TWFunc::File_Property_Get ("/default.prop", "ro.build.date");
              		if (fox_build_date == "")
                 		fox_build_date = "[no date!]";
         	}
     	}
		 
  	DataManager::SetValue("FOX_BUILD_DATE_REAL", fox_build_date);

  	// Set the start date to the recovery's build date
  	TWFunc::Reset_Clock();

  	DataManager::GetValue(FOX_COMPATIBILITY_DEVICE, Fox_Current_Device);
  	printf("Starting OrangeFox Recovery %s [%s, core: %s] (built on %s for %s [dev_ver: %s]; pid %d)\n",
  		FOX_BUILD, FOX_VARIANT, FOX_MAIN_VERSION_STR, fox_build_date.c_str(), Fox_Current_Device.c_str(), FOX_CURRENT_DEV_STR, getpid());

	// refresh the specific device codename if we have a generic unified codename
	TWFunc::Fox_Set_Current_Device_CodeName();

	// Load default values to set DataManager constants and handle ifdefs
	DataManager::SetDefaultValues();

	startupArgs startup;
	startup.parse(&argc, &argv);
	android::base::SetProperty(TW_FASTBOOT_MODE_PROP, startup.Get_Fastboot_Mode() ? "1" : "0");
	printf("=> Linking mtab\n");
	symlink("/proc/mounts", "/etc/mtab");
	std::string fstab_filename = "/etc/twrp.fstab";
	if (!TWFunc::Path_Exists(fstab_filename)) {
		fstab_filename = "/etc/recovery.fstab";
	}
	printf("=> Processing %s\n", fstab_filename.c_str());
	if (!PartitionManager.Process_Fstab(fstab_filename, 1, !startup.Get_Fastboot_Mode())) {
		LOGERR("Failing out of recovery due to problem with fstab.\n");
		return -1;
	}

	// Set the props for OrangeFox dynamic partitions
	//PartitionManager.Fox_Set_Dynamic_Partition_Props();

	// start the UI
	printf("Starting the UI...\n");
	gui_init();

	if (!startup.Get_Fastboot_Mode()) PartitionManager.Setup_Fstab_Partitions(true);

	// Load up all the resources
	gui_loadResources();

	std::string value;
	static char charging = ' ';
	static int lastVal = -1;

	// Function to monitor battery in the background
	auto monitorBatteryInBackground = [&]() {
		while (true) {
#ifdef TW_USE_LEGACY_BATTERY_SERVICES
			char cap_s[4];
#ifdef TW_CUSTOM_BATTERY_PATH
			string capacity_file = EXPAND(TW_CUSTOM_BATTERY_PATH);
			capacity_file += "/capacity";
			FILE * cap = fopen(capacity_file.c_str(),"rt");
#else
			FILE * cap = fopen("/sys/class/power_supply/battery/capacity","rt");
#endif
			if (cap) {
				fgets(cap_s, 4, cap);
				fclose(cap);
				lastVal = atoi(cap_s);
				if (lastVal > 100)	lastVal = 101;
				if (lastVal < 0)	lastVal = 0;
			}
#ifdef TW_CUSTOM_BATTERY_PATH
			string status_file = EXPAND(TW_CUSTOM_BATTERY_PATH);
			status_file += "/status";
			cap = fopen(status_file.c_str(),"rt");
#else
			cap = fopen("/sys/class/power_supply/battery/status","rt");
#endif
			if (cap) {
				fgets(cap_s, 2, cap);
				fclose(cap);
				if (cap_s[0] == 'C')
					charging = '+';
				else
					charging = ' ';
			}
#else // TW_USE_LEGACY_BATTERY_SERVICES
			auto battery_info = GetBatteryInfo();
			if (battery_info.charging) {
				charging = '+';
			} else {
				charging = ' ';
			}
			lastVal = battery_info.capacity;
#endif // TW_USE_LEGACY_BATTERY_SERVICES
			// Format the value based on the background updates
			value = std::to_string(lastVal);

			DataManager::SetValue("tw_battery_charge", value + "%" + charging);
			DataManager::SetValue("tw_battery", value);
			DataManager::SetValue("charging_now", (charging == '+') ? "1" : "0");

			// Sleep for a specified interval (e.g., 1 second) before checking again
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	};

	// Create a thread for battery monitoring
	static std::thread battery_monitor(monitorBatteryInBackground);

#ifdef FOX_SETTINGS_ROOT_DIRECTORY
	// Language
	PageManager::LoadLanguage(DataManager::GetStrValue("tw_language"));
	GUIConsole::Translate_Now();
#endif

	twrpAdbBuFifo *adb_bu_fifo = new twrpAdbBuFifo();
	TWFunc::Clear_Bootloader_Message();

	if (startup.Get_Fastboot_Mode()) {
		process_fastbootd_mode();
		delete adb_bu_fifo;
		TWFunc::Update_Intent_File(startup.Get_Intent());
		reboot();
		return 0;
	} else {
		process_recovery_mode(adb_bu_fifo, startup.Should_Skip_Decryption());
	}

#ifndef FOX_SETTINGS_ROOT_DIRECTORY
	// Language
	PageManager::LoadLanguage(DataManager::GetStrValue("tw_language"));
	GUIConsole::Translate_Now();
#endif

	// Fox extra setup
  	TWFunc::Setup_Verity_Forced_Encryption();

	// Launch the main GUI
	if (Fox_CheckReload_Themes()) {
		//[f/d] Start UI using reapply_settings page (executed on recovery startup)
		DataManager::SetValue("of_reload_back", "main");
		PageManager::RequestReload();
		gui_startPage("reapply_settings", 1, 0);
	} else gui_start();

	delete adb_bu_fifo;
	TWFunc::Update_Intent_File(startup.Get_Intent());

	reboot();

	return 0;
}
