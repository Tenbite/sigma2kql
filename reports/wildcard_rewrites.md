# Wildcard rewrites

The backend left a Sigma `*` wildcard inside a `contains`/`endswith`/`==` comparison in these rules. KQL treats that as a literal asterisk, so the comparison would never match. Each one was rewritten to an equivalent case-insensitive `matches regex` and then validated.

| Rule | Level | Rewrites | KQL |
|---|---|---|---|
| OceanLotus Registry Activity | critical | 7 | [registry_event_apt_oceanlotus_registry.kql](../kql/rules-emerging-threats/2018/TA/APT32-Oceanlotus/registry_event_apt_oceanlotus_registry.kql) |
| Potential Ryuk Ransomware Activity | high | 3 | [proc_creation_win_malware_ryuk.kql](../kql/rules-emerging-threats/2019/Malware/Ryuk/proc_creation_win_malware_ryuk.kql) |
| FlowCloud Registry Markers | critical | 1 | [registry_event_malware_flowcloud_markers.kql](../kql/rules-emerging-threats/2020/Malware/FlowCloud/registry_event_malware_flowcloud_markers.kql) |
| PrinterNightmare Mimikatz Driver Name | critical | 1 | [registry_event_cve_2021_1675_mimikatz_printernightmare_drivers.kql](../kql/rules-emerging-threats/2021/Exploits/CVE-2021-1675/registry_event_cve_2021_1675_mimikatz_printernightmare_drivers.kql) |
| Small Sieve Malware Registry Persistence | high | 1 | [registry_set_malware_small_sieve_evasion_typo.kql](../kql/rules-emerging-threats/2021/Malware/Small-Sieve/registry_set_malware_small_sieve_evasion_typo.kql) |
| Suspicious Set Value of MSDT in Registry (CVE-2022-30190) | medium | 1 | [registry_set_exploit_cve_2022_30190_msdt_follina.kql](../kql/rules-emerging-threats/2022/Exploits/CVE-2022-30190/registry_set_exploit_cve_2022_30190_msdt_follina.kql) |
| Potential Encrypted Registry Blob Related To SNAKE Malware | medium | 1 | [registry_set_malware_snake_encrypted_key.kql](../kql/rules-emerging-threats/2023/Malware/SNAKE/registry_set_malware_snake_encrypted_key.kql) |
| Ursnif Redirection Of Discovery Commands | high | 1 | [proc_creation_win_malware_ursnif_cmd_redirection.kql](../kql/rules-emerging-threats/2023/Malware/Ursnif/proc_creation_win_malware_ursnif_cmd_redirection.kql) |
| Diamond Sleet APT Scheduled Task Creation - Registry | high | 1 | [registry_event_apt_diamond_sleet_scheduled_task.kql](../kql/rules-emerging-threats/2023/TA/Diamond-Sleet/registry_event_apt_diamond_sleet_scheduled_task.kql) |
| Peach Sandstorm APT Process Activity Indicators | high | 1 | [proc_creation_win_apt_peach_sandstorm_indicators.kql](../kql/rules-emerging-threats/2023/TA/Peach-Sandstorm/proc_creation_win_apt_peach_sandstorm_indicators.kql) |
| Manual Execution of Script Inside of a Compressed File | medium | 2 | [proc_creation_win_susp_script_exec_from_compressed_parent.kql](../kql/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_script_exec_from_compressed_parent.kql) |
| Service Binary in User Controlled Folder | medium | 2 | [registry_set_service_image_path_user_controlled_folder.kql](../kql/rules-threat-hunting/windows/registry/registry_set/registry_set_service_image_path_user_controlled_folder.kql) |
| Windows Defender Exclusion List Modified | medium | 1 | [win_security_windows_defender_exclusions_registry_modified.kql](../kql/rules/windows/builtin/security/win_security_windows_defender_exclusions_registry_modified.kql) |
| Hiding Files with Attrib.exe | medium | 2 | [proc_creation_win_attrib_hiding_files.kql](../kql/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.kql) |
| Greedy File Deletion Using Del | medium | 4 | [proc_creation_win_cmd_del_greedy_deletion.kql](../kql/rules/windows/process_creation/proc_creation_win_cmd_del_greedy_deletion.kql) |
| Microsoft IIS Service Account Password Dumped | high | 1 | [proc_creation_win_iis_appcmd_service_account_password_dumped.kql](../kql/rules/windows/process_creation/proc_creation_win_iis_appcmd_service_account_password_dumped.kql) |
| Computer Discovery And Export Via Get-ADComputer Cmdlet | medium | 1 | [proc_creation_win_powershell_computer_discovery_get_adcomputer.kql](../kql/rules/windows/process_creation/proc_creation_win_powershell_computer_discovery_get_adcomputer.kql) |
| PowerShell Execution With Potential Decryption Capabilities | high | 2 | [proc_creation_win_powershell_decrypt_pattern.kql](../kql/rules/windows/process_creation/proc_creation_win_powershell_decrypt_pattern.kql) |
| User Discovery And Export Via Get-ADUser Cmdlet | medium | 1 | [proc_creation_win_powershell_user_discovery_get_aduser.kql](../kql/rules/windows/process_creation/proc_creation_win_powershell_user_discovery_get_aduser.kql) |
| Suspicious Greedy Compression Using Rar.EXE | high | 2 | [proc_creation_win_rar_susp_greedy_compression.kql](../kql/rules/windows/process_creation/proc_creation_win_rar_susp_greedy_compression.kql) |
| Delete All Scheduled Tasks | high | 1 | [proc_creation_win_schtasks_delete_all.kql](../kql/rules/windows/process_creation/proc_creation_win_schtasks_delete_all.kql) |
| Potential Persistence Via Disk Cleanup Handler - Registry | medium | 1 | [registry_add_persistence_disk_cleanup_handler_entry.kql](../kql/rules/windows/registry/registry_add/registry_add_persistence_disk_cleanup_handler_entry.kql) |
| Terminal Server Client Connection History Cleared - Registry | high | 1 | [registry_delete_mstsc_history_cleared.kql](../kql/rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.kql) |
| Removal of Potential COM Hijacking Registry Keys | medium | 1 | [registry_delete_removal_com_hijacking_registry_key.kql](../kql/rules/windows/registry/registry_delete/registry_delete_removal_com_hijacking_registry_key.kql) |
| Removal Of Index Value to Hide Schedule Task - Registry | medium | 1 | [registry_delete_schtasks_hide_task_via_index_value_removal.kql](../kql/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_index_value_removal.kql) |
| Removal Of SD Value to Hide Schedule Task - Registry | medium | 1 | [registry_delete_schtasks_hide_task_via_sd_value_removal.kql](../kql/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.kql) |
| Creation of a Local Hidden User Account by Registry | high | 1 | [registry_event_add_local_hidden_user.kql](../kql/rules/windows/registry/registry_event/registry_event_add_local_hidden_user.kql) |
| CMSTP App Paths Registry Key Modification | high | 1 | [registry_event_cmstp_execution_by_registry.kql](../kql/rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.kql) |
| Registry Entries For Azorult Malware | critical | 1 | [registry_event_mal_azorult.kql](../kql/rules/windows/registry/registry_event/registry_event_mal_azorult.kql) |
| NetNTLM Downgrade Attack - Registry | high | 1 | [registry_event_net_ntlm_downgrade.kql](../kql/rules/windows/registry/registry_event/registry_event_net_ntlm_downgrade.kql) |
| New PortProxy Registry Entry Added | medium | 1 | [registry_event_portproxy_registry_key.kql](../kql/rules/windows/registry/registry_event/registry_event_portproxy_registry_key.kql) |
| Suspicious Camera and Microphone Access | high | 1 | [registry_event_susp_mic_cam_access.kql](../kql/rules/windows/registry/registry_event/registry_event_susp_mic_cam_access.kql) |
| Registry Persistence via Service in Safe Mode | high | 2 | [registry_set_add_load_service_in_safe_mode.kql](../kql/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.kql) |
| Add Port Monitor Persistence in Registry | medium | 3 | [registry_set_add_port_monitor.kql](../kql/rules/windows/registry/registry_set/registry_set_add_port_monitor.kql) |
| Classes Autorun Keys Modification | medium | 1 | [registry_set_asep_reg_keys_modification_classes.kql](../kql/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_classes.kql) |
| Common Autorun Keys Modification | medium | 2 | [registry_set_asep_reg_keys_modification_common.kql](../kql/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_common.kql) |
| CurrentVersion Autorun Keys Modification | medium | 10 | [registry_set_asep_reg_keys_modification_currentversion.kql](../kql/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.kql) |
| CurrentVersion NT Autorun Keys Modification | medium | 4 | [registry_set_asep_reg_keys_modification_currentversion_nt.kql](../kql/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.kql) |
| Office Autorun Keys Modification | medium | 18 | [registry_set_asep_reg_keys_modification_office.kql](../kql/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_office.kql) |
| Wow6432Node CurrentVersion Autorun Keys Modification | medium | 8 | [registry_set_asep_reg_keys_modification_wow6432node.kql](../kql/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node.kql) |
| New BgInfo.EXE Custom VBScript Registry Configuration | medium | 1 | [registry_set_bginfo_custom_vbscript.kql](../kql/rules/windows/registry/registry_set/registry_set_bginfo_custom_vbscript.kql) |
| New BgInfo.EXE Custom WMI Query Registry Configuration | medium | 1 | [registry_set_bginfo_custom_wmi_query.kql](../kql/rules/windows/registry/registry_set/registry_set_bginfo_custom_wmi_query.kql) |
| IE Change Domain Zone | medium | 1 | [registry_set_change_security_zones.kql](../kql/rules/windows/registry/registry_set/registry_set_change_security_zones.kql) |
| Sysmon Driver Altitude Change | high | 1 | [registry_set_change_sysmon_driver_altitude.kql](../kql/rules/windows/registry/registry_set/registry_set_change_sysmon_driver_altitude.kql) |
| Change Winevt Channel Access Permission Via Registry | high | 1 | [registry_set_change_winevt_channelaccess.kql](../kql/rules/windows/registry/registry_set/registry_set_change_winevt_channelaccess.kql) |
| ClickOnce Trust Prompt Tampering | medium | 1 | [registry_set_clickonce_trust_prompt.kql](../kql/rules/windows/registry/registry_set/registry_set_clickonce_trust_prompt.kql) |
| Service Binary in Suspicious Folder | high | 2 | [registry_set_creation_service_susp_folder.kql](../kql/rules/windows/registry/registry_set/registry_set_creation_service_susp_folder.kql) |
| Custom File Open Handler Executes PowerShell | high | 1 | [registry_set_custom_file_open_handler_powershell_execution.kql](../kql/rules/windows/registry/registry_set/registry_set_custom_file_open_handler_powershell_execution.kql) |
| Disable Administrative Share Creation at Startup | medium | 1 | [registry_set_disable_administrative_share.kql](../kql/rules/windows/registry/registry_set/registry_set_disable_administrative_share.kql) |
| Potential AutoLogger Sessions Tampering | high | 3 | [registry_set_disable_autologger_sessions.kql](../kql/rules/windows/registry/registry_set/registry_set_disable_autologger_sessions.kql) |
| Disable Microsoft Defender Firewall via Registry | medium | 1 | [registry_set_disable_defender_firewall.kql](../kql/rules/windows/registry/registry_set/registry_set_disable_defender_firewall.kql) |
| Disable Macro Runtime Scan Scope | high | 2 | [registry_set_disable_macroruntimescanscope.kql](../kql/rules/windows/registry/registry_set/registry_set_disable_macroruntimescanscope.kql) |
| Disable Windows Event Logging Via Registry | high | 5 | [registry_set_disable_winevt_logging.kql](../kql/rules/windows/registry/registry_set/registry_set_disable_winevt_logging.kql) |
| Persistence Via Disk Cleanup Handler - Autorun | medium | 1 | [registry_set_disk_cleanup_handler_autorun_persistence.kql](../kql/rules/windows/registry/registry_set/registry_set_disk_cleanup_handler_autorun_persistence.kql) |
| Potential EventLog File Location Tampering | high | 1 | [registry_set_evtx_file_key_tamper.kql](../kql/rules/windows/registry/registry_set/registry_set_evtx_file_key_tamper.kql) |
| Suspicious Application Allowed Through Exploit Guard | high | 5 | [registry_set_exploit_guard_susp_allowed_apps.kql](../kql/rules/windows/registry/registry_set/registry_set_exploit_guard_susp_allowed_apps.kql) |
| Change the Fax Dll | high | 1 | [registry_set_fax_dll_persistance.kql](../kql/rules/windows/registry/registry_set/registry_set_fax_dll_persistance.kql) |
| Hide Schedule Task Via Index Value Tamper | high | 1 | [registry_set_hide_scheduled_task_via_index_tamper.kql](../kql/rules/windows/registry/registry_set/registry_set_hide_scheduled_task_via_index_tamper.kql) |
| Driver Added To Disallowed Images In HVCI - Registry | high | 1 | [registry_set_hvci_disallowed_images.kql](../kql/rules/windows/registry/registry_set/registry_set_hvci_disallowed_images.kql) |
| Uncommon Extension In Keyboard Layout IME File Registry Value | high | 1 | [registry_set_ime_non_default_extension.kql](../kql/rules/windows/registry/registry_set/registry_set_ime_non_default_extension.kql) |
| Suspicious Path In Keyboard Layout IME File Registry Value | high | 1 | [registry_set_ime_suspicious_paths.kql](../kql/rules/windows/registry/registry_set/registry_set_ime_suspicious_paths.kql) |
| New Root or CA or AuthRoot Certificate to Store | medium | 9 | [registry_set_install_root_or_ca_certificat.kql](../kql/rules/windows/registry/registry_set/registry_set_install_root_or_ca_certificat.kql) |
| Potential Credential Dumping Attempt Using New NetworkProvider - REG | medium | 1 | [registry_set_new_network_provider.kql](../kql/rules/windows/registry/registry_set/registry_set_new_network_provider.kql) |
| Potentially Suspicious ODBC Driver Registered | high | 1 | [registry_set_odbc_driver_registered_susp.kql](../kql/rules/windows/registry/registry_set/registry_set_odbc_driver_registered_susp.kql) |
| Microsoft Office Protected View Disabled | high | 2 | [registry_set_office_disable_protected_view_features.kql](../kql/rules/windows/registry/registry_set/registry_set_office_disable_protected_view_features.kql) |
| Python Function Execution Security Warning Disabled In Excel - Registry | high | 1 | [registry_set_office_disable_python_security_warnings.kql](../kql/rules/windows/registry/registry_set/registry_set_office_disable_python_security_warnings.kql) |
| Outlook Security Settings Updated - Registry | medium | 2 | [registry_set_office_outlook_security_settings.kql](../kql/rules/windows/registry/registry_set/registry_set_office_outlook_security_settings.kql) |
| Potential Persistence Via New AMSI Providers - Registry | medium | 2 | [registry_set_persistence_amsi_providers.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_amsi_providers.kql) |
| Potential Persistence Via AppCompat RegisterAppRestart Layer | medium | 1 | [registry_set_persistence_app_cpmpat_layer_registerapprestart.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_app_cpmpat_layer_registerapprestart.kql) |
| Potential COM Object Hijacking Via TreatAs Subkey - Registry | medium | 2 | [registry_set_persistence_com_key_linking.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_com_key_linking.kql) |
| Potential Persistence Via Custom Protocol Handler | medium | 1 | [registry_set_persistence_custom_protocol_handler.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_custom_protocol_handler.kql) |
| Potential Persistence Via GlobalFlags | high | 4 | [registry_set_persistence_globalflags.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_globalflags.kql) |
| Register New IFiltre For Persistence | medium | 27 | [registry_set_persistence_ifilter.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_ifilter.kql) |
| Potential Persistence Via DLLPathOverride | high | 1 | [registry_set_persistence_natural_language.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_natural_language.kql) |
| Potential Persistence Via Visual Studio Tools for Office | medium | 7 | [registry_set_persistence_office_vsto.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_office_vsto.kql) |
| Potential Persistence Via Outlook Home Page | high | 2 | [registry_set_persistence_outlook_homepage.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.kql) |
| Potential Persistence Via Outlook Today Page | high | 2 | [registry_set_persistence_outlook_todaypage.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_outlook_todaypage.kql) |
| Potential Persistence Via Shim Database Modification | medium | 2 | [registry_set_persistence_shim_database.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_shim_database.kql) |
| Suspicious Shim Database Patching Activity | high | 1 | [registry_set_persistence_shim_database_susp_application.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_shim_database_susp_application.kql) |
| Potential Persistence Via Shim Database In Uncommon Location | high | 1 | [registry_set_persistence_shim_database_uncommon_location.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_shim_database_uncommon_location.kql) |
| Potential Persistence Via TypedPaths | high | 1 | [registry_set_persistence_typed_paths.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_typed_paths.kql) |
| Potential Persistence Via Excel Add-in - Registry | high | 1 | [registry_set_persistence_xll.kql](../kql/rules/windows/registry/registry_set/registry_set_persistence_xll.kql) |
| Potential Attachment Manager Settings Associations Tamper | high | 1 | [registry_set_policies_associations_tamper.kql](../kql/rules/windows/registry/registry_set/registry_set_policies_associations_tamper.kql) |
| Potential Attachment Manager Settings Attachments Tamper | high | 1 | [registry_set_policies_attachments_tamper.kql](../kql/rules/windows/registry/registry_set/registry_set_policies_attachments_tamper.kql) |
| PowerShell as a Service in Registry | high | 1 | [registry_set_powershell_as_service.kql](../kql/rules/windows/registry/registry_set/registry_set_powershell_as_service.kql) |
| PowerShell Logging Disabled Via Registry Key Tampering | high | 2 | [registry_set_powershell_logging_disabled.kql](../kql/rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.kql) |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG | high | 1 | [registry_set_provisioning_command_abuse.kql](../kql/rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.kql) |
| Potential SentinelOne Shell Context Menu Scan Command Tampering | medium | 1 | [registry_set_sentinelone_shell_context_tampering.kql](../kql/rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.kql) |
| ServiceDll Hijack | medium | 2 | [registry_set_servicedll_hijack.kql](../kql/rules/windows/registry/registry_set/registry_set_servicedll_hijack.kql) |
| Persistence Via New SIP Provider | medium | 2 | [registry_set_sip_persistence.kql](../kql/rules/windows/registry/registry_set/registry_set_sip_persistence.kql) |
| Suspicious Keyboard Layout Load | medium | 2 | [registry_set_susp_keyboard_layout_load.kql](../kql/rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.kql) |
| Suspicious Printer Driver Empty Manufacturer | high | 4 | [registry_set_susp_printer_driver.kql](../kql/rules/windows/registry/registry_set/registry_set_susp_printer_driver.kql) |
| Suspicious Environment Variable Has Been Registered | high | 1 | [registry_set_suspicious_env_variables.kql](../kql/rules/windows/registry/registry_set/registry_set_suspicious_env_variables.kql) |
| Scheduled TaskCache Change by Uncommon Program | high | 2 | [registry_set_taskcache_entry.kql](../kql/rules/windows/registry/registry_set/registry_set_taskcache_entry.kql) |
| Potential Registry Persistence Attempt Via Windows Telemetry | high | 1 | [registry_set_telemetry_persistence.kql](../kql/rules/windows/registry/registry_set/registry_set_telemetry_persistence.kql) |
| RDP Sensitive Settings Changed | high | 4 | [registry_set_terminal_server_tampering.kql](../kql/rules/windows/registry/registry_set/registry_set_terminal_server_tampering.kql) |
| Old TLS1.0/TLS1.1 Protocol Version Enabled | medium | 2 | [registry_set_tls_protocol_old_version_enabled.kql](../kql/rules/windows/registry/registry_set/registry_set_tls_protocol_old_version_enabled.kql) |
| Potential Signing Bypass Via Windows Developer Features - Registry | high | 1 | [registry_set_turn_on_dev_features.kql](../kql/rules/windows/registry/registry_set/registry_set_turn_on_dev_features.kql) |
| VBScript Payload Stored in Registry | high | 1 | [registry_set_vbs_payload_stored.kql](../kql/rules/windows/registry/registry_set/registry_set_vbs_payload_stored.kql) |
| Disable Windows Defender Functionalities Via Registry Keys | high | 3 | [registry_set_windows_defender_tamper.kql](../kql/rules/windows/registry/registry_set/registry_set_windows_defender_tamper.kql) |
