# Pending rules from open SigmaHQ pull requests

> [!CAUTION]
> These rules come from **open pull requests that SigmaHQ has not reviewed or merged**. They may change, be rejected, or be wrong. Machine-converted and untested. Use for early hunting only.

Rebuilt 2026-11-26 17:04 UTC from 300 open pull requests. When a pull request is merged or closed, its pending rules are removed automatically on the next run.

## [#6673](https://github.com/SigmaHQ/sigma/pull/6673) Add logsource definition for the CommandLine requirement in two Exchange file_event rules

| Rule | Change | Level |
|---|---|---|
| [Suspicious ASPX File Drop by Exchange](pr-6673/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.kql) | update to existing rule | high |
| [Suspicious File Drop by Exchange](pr-6673/rules/windows/file/file_event/file_event_win_exchange_webshell_drop_suspicious.kql) | update to existing rule | medium |

## [#6669](https://github.com/SigmaHQ/sigma/pull/6669) fix: catastrophic backtracking in three Invoke-Obfuscation VAR+ Launcher rules

| Rule | Change | Level |
|---|---|---|
| [Invoke-Obfuscation VAR+ Launcher](pr-6669/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_var.kql) | update to existing rule | high |

## [#6667](https://github.com/SigmaHQ/sigma/pull/6667) new: DRV File Created In User AppData Folder

| Rule | Change | Level |
|---|---|---|
| [DRV File Created In User AppData Folder](pr-6667/rules/windows/file/file_event/file_event_win_susp_drv_file_creation_appdata.kql) | new rule | medium |

## [#6666](https://github.com/SigmaHQ/sigma/pull/6666) new: Inno Setup Uninstaller Created In Windows Root Folder

| Rule | Change | Level |
|---|---|---|
| [Inno Setup Uninstaller Created In Windows Root Folder](pr-6666/rules/windows/file/file_event/file_event_win_susp_inno_setup_uninstaller_windows_root.kql) | new rule | medium |

## [#6660](https://github.com/SigmaHQ/sigma/pull/6660) new: FluxEngine banker rules (registry keys, Run key, attrib.exe hollowing host, Cloudflare API dead drop, stage download)

| Rule | Change | Level |
|---|---|---|
| [FluxEngine Banker Attrib.EXE Spawned By Renamed AutoIt Host](pr-6660/rules-emerging-threats/2026/Malware/FluxEngine/proc_creation_win_malware_fluxengine_attrib_from_autoit.kql) | new rule | high |
| [FluxEngine Banker Registry Key Write](pr-6660/rules-emerging-threats/2026/Malware/FluxEngine/registry_set_malware_fluxengine_desktop_key.kql) | new rule | high |
| [FluxEngine Banker Fake HWiNFO32 Sensor Value Write](pr-6660/rules-emerging-threats/2026/Malware/FluxEngine/registry_set_malware_fluxengine_hwinfo_bsource_cache.kql) | new rule | high |
| [Potential FluxEngine Banker Run Key Persistence](pr-6660/rules-emerging-threats/2026/Malware/FluxEngine/registry_set_malware_fluxengine_run_key_root_folder.kql) | new rule | medium |

## [#6659](https://github.com/SigmaHQ/sigma/pull/6659) new: Transparent Tribe (APT36) PcDirvs loader, public core HTA and Crimson RAT runner

| Rule | Change | Level |
|---|---|---|
| [Transparent Tribe PcDirvs Loader File Creation](pr-6659/rules-emerging-threats/2025/TA/Transparent-Tribe/file_event_win_apt_transparent_tribe_pcdirvs_loader.kql) | new rule | high |
| [Transparent Tribe HTA Dropped In Public Core Folder](pr-6659/rules-emerging-threats/2025/TA/Transparent-Tribe/file_event_win_apt_transparent_tribe_public_core_hta.kql) | new rule | high |
| [Transparent Tribe Crimson RAT Batch Runner Execution](pr-6659/rules-emerging-threats/2026/TA/Transparent-Tribe/proc_creation_win_apt_transparent_tribe_crimson_rat_runner.kql) | new rule | high |

## [#6650](https://github.com/SigmaHQ/sigma/pull/6650) Real firas patch 2

| Rule | Change | Level |
|---|---|---|
| [Potential Binary Proxy Execution Via DbgSrv.EXE](pr-6650/rules/windows/process_creation/proc_creation_win_lolbin_dbgsrv.kql) | new rule | medium |

## [#6648](https://github.com/SigmaHQ/sigma/pull/6648) new: Potential Python Startup Hook Customize File Created - Linux

| Rule | Change | Level |
|---|---|---|
| [Potential Python Startup Hook Customize File Created - Linux](pr-6648/rules/linux/file_event/file_event_lnx_python_startup_hook_customize_file.kql) | new rule | medium |

## [#6647](https://github.com/SigmaHQ/sigma/pull/6647) new: Potential Cloud Access Token Or Secret Retrieval Via Cloud CLI

| Rule | Change | Level |
|---|---|---|
| [Potential Cloud Access Token Or Secret Retrieval Via Cloud CLI](pr-6647/rules-threat-hunting/windows/process_creation/proc_creation_win_cloud_cli_token_and_secret_retrieval.kql) | new rule | medium |

## [#6646](https://github.com/SigmaHQ/sigma/pull/6646) update: Python Path Configuration File Creation - Windows - match .pth in any site-packages directory

| Rule | Change | Level |
|---|---|---|
| [Python Path Configuration File Creation - Windows](pr-6646/rules-threat-hunting/windows/file/file_event/file_event_win_python_path_configuration_files.kql) | update to existing rule | medium |

## [#6643](https://github.com/SigmaHQ/sigma/pull/6643) new: Potential Cloud Instance Metadata Credential Or Token Request Via CLI - Linux

| Rule | Change | Level |
|---|---|---|
| [Potential Cloud Instance Metadata Credential Or Token Request Via CLI - Linux](pr-6643/rules/linux/process_creation/proc_creation_lnx_cloud_imds_credential_request.kql) | new rule | medium |

## [#6641](https://github.com/SigmaHQ/sigma/pull/6641) chore: use en-us Microsoft Learn links in rule references

| Rule | Change | Level |
|---|---|---|
| [Potential Secure Deletion with SDelete](pr-6641/rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.kql) | update to existing rule | medium |
| [ADExplorer Writing Complete AD Snapshot Into .dat File](pr-6641/rules/windows/file/file_event/file_event_win_sysinternals_adexplorer_dump_written.kql) | update to existing rule | medium |
| [Potentially Suspicious NTFS Symlink Behavior Modification](pr-6641/rules/windows/process_creation/proc_creation_win_fsutil_symlinkevaluation.kql) | update to existing rule | medium |
| [Computer Password Change Via Ksetup.EXE](pr-6641/rules/windows/process_creation/proc_creation_win_ksetup_password_change_computer.kql) | update to existing rule | medium |
| [Logged-On User Password Change Via Ksetup.EXE](pr-6641/rules/windows/process_creation/proc_creation_win_ksetup_password_change_user.kql) | update to existing rule | medium |
| [Suspicious Service DACL Modification Via Set-Service Cmdlet](pr-6641/rules/windows/process_creation/proc_creation_win_powershell_service_dacl_modification_set_service.kql) | update to existing rule | high |
| [Potential PowerShell Execution Policy Tampering - ProcCreation](pr-6641/rules/windows/process_creation/proc_creation_win_registry_set_unsecure_powershell_policy.kql) | update to existing rule | high |
| [Active Directory Database Snapshot Via ADExplorer](pr-6641/rules/windows/process_creation/proc_creation_win_sysinternals_adexplorer_execution.kql) | update to existing rule | medium |
| [Suspicious Active Directory Database Snapshot Via ADExplorer](pr-6641/rules/windows/process_creation/proc_creation_win_sysinternals_adexplorer_susp_execution.kql) | update to existing rule | high |

## [#6638](https://github.com/SigmaHQ/sigma/pull/6638) New Rule: Uncommon Child Process Of WFMFormat.EXE

| Rule | Change | Level |
|---|---|---|
| [Uncommon Child Process Of WFMFormat.EXE](pr-6638/rules/windows/process_creation/proc_creation_win_wfmformat_uncommon_child_process.kql) | new rule | medium |

## [#6637](https://github.com/SigmaHQ/sigma/pull/6637) New Rule: Arbitrary File Copy Via Dtutil.EXE

| Rule | Change | Level |
|---|---|---|
| [Arbitrary File Copy Via Dtutil.EXE](pr-6637/rules/windows/process_creation/proc_creation_win_dtutil_file_copy.kql) | new rule | medium |

## [#6632](https://github.com/SigmaHQ/sigma/pull/6632) new: Cloud Instance Metadata API Query for Credential Theft (T1552.005)

| Rule | Change | Level |
|---|---|---|
| [Cloud Instance Metadata API Query for Credential Theft](pr-6632/rules/linux/process_creation/proc_creation_lnx_cloud_imds_credential_theft.kql) | new rule | medium |

## [#6631](https://github.com/SigmaHQ/sigma/pull/6631) fix(rules): replace unreachable Lab52 reference URL in proc_creation_win_powershell_download_patterns.yml

| Rule | Change | Level |
|---|---|---|
| [PowerShell Download Pattern](pr-6631/rules/windows/process_creation/proc_creation_win_powershell_download_patterns.kql) | update to existing rule | medium |

## [#6629](https://github.com/SigmaHQ/sigma/pull/6629) new: Suspicious QoS Policy Throttling Security Product Network Traffic

| Rule | Change | Level |
|---|---|---|
| [Suspicious QoS Policy Throttling Security Product Network Traffic](pr-6629/rules/windows/process_creation/proc_creation_win_powershell_netqospolicy_throttle_security_product.kql) | new rule | high |

## [#6627](https://github.com/SigmaHQ/sigma/pull/6627) new: Suspicious Svchost Lookalike Process Name Execution

| Rule | Change | Level |
|---|---|---|
| [Suspicious Svchost Lookalike Process Name Execution](pr-6627/rules/windows/process_creation/proc_creation_win_susp_svchost_lookalike_name.kql) | new rule | high |

## [#6626](https://github.com/SigmaHQ/sigma/pull/6626) new: Suspicious Renamed MSBuild Execution

| Rule | Change | Level |
|---|---|---|
| [Suspicious Renamed MSBuild Execution](pr-6626/rules/windows/process_creation/proc_creation_win_renamed_msbuild.kql) | new rule | high |

## [#6624](https://github.com/SigmaHQ/sigma/pull/6624) new: Suspicious LSA Protection Downgrade Via RunAsPPL Registry Value

| Rule | Change | Level |
|---|---|---|
| [Suspicious LSA Protection Downgrade Via RunAsPPL Registry Value](pr-6624/rules/windows/registry/registry_set/registry_set_lsa_ppl_protection_disabled.kql) | new rule | high |

## [#6620](https://github.com/SigmaHQ/sigma/pull/6620) fix: restore the missing ProgramData quote in two autorun rules

| Rule | Change | Level |
|---|---|---|
| [Suspicious Autorun Registry Modified via WMI](pr-6620/rules/windows/process_creation/proc_creation_win_autorun_registry_modified_via_wmic.kql) | update to existing rule | high |
| [New RUN Key Pointing to Suspicious Folder](pr-6620/rules/windows/registry/registry_set/registry_set_susp_run_key_img_folder.kql) | update to existing rule | high |

## [#6619](https://github.com/SigmaHQ/sigma/pull/6619) Add `windash` to "Schtasks Creation Or Modification With SYSTEM Privileges"

| Rule | Change | Level |
|---|---|---|
| [Schtasks Creation Or Modification With SYSTEM Privileges](pr-6619/rules/windows/process_creation/proc_creation_win_schtasks_system.kql) | update to existing rule | high |

## [#6617](https://github.com/SigmaHQ/sigma/pull/6617) fix: UAC Bypass via Sdclt - also match the user classes hive written as <SID>_Classes

| Rule | Change | Level |
|---|---|---|
| [UAC Bypass via Sdclt](pr-6617/rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.kql) | update to existing rule | high |

## [#6615](https://github.com/SigmaHQ/sigma/pull/6615) New: ScreenConnect Client Spawns Script Host / Run Key Set To Launch VBScript

| Rule | Change | Level |
|---|---|---|
| [Remote Access Tool - ScreenConnect Client Spawns Script Host](pr-6615/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_susp_child_script_host.kql) | new rule | high |
| [Run Key Set To Launch VBScript Via Script Host](pr-6615/rules/windows/registry/registry_set/registry_set_persistence_run_key_vbscript.kql) | new rule | medium |

## [#6614](https://github.com/SigmaHQ/sigma/pull/6614) new: MioLab macOS stealer rules (agent process, persistence files, C2 domains, C2 proxy URIs)

| Rule | Change | Level |
|---|---|---|
| [Suspicious MioLab LaunchAgent Or Staging File Creation](pr-6614/rules-emerging-threats/2026/Malware/MioLab/file_event_macos_malware_miolab_persistence_indicators.kql) | new rule | high |
| [Suspicious MioLab Agent Process Activity](pr-6614/rules-emerging-threats/2026/Malware/MioLab/proc_creation_macos_malware_miolab_agent_activity.kql) | new rule | high |

## [#6613](https://github.com/SigmaHQ/sigma/pull/6613) new: RevStealer rules (C2 domain, gate URI, Telegraph and Polygon dead drops, renamed OneDrive host)

| Rule | Change | Level |
|---|---|---|
| [Renamed OneDrive Client Execution](pr-6613/rules/windows/process_creation/proc_creation_win_renamed_onedrive.kql) | new rule | medium |

## [#6611](https://github.com/SigmaHQ/sigma/pull/6611) fix: escaped wildcards in two rules that can never match

| Rule | Change | Level |
|---|---|---|
| [Ursnif Redirection Of Discovery Commands](pr-6611/rules-emerging-threats/2023/Malware/Ursnif/proc_creation_win_malware_ursnif_cmd_redirection.kql) | update to existing rule | high |
| [Manual Execution of Script Inside of a Compressed File](pr-6611/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_script_exec_from_compressed_parent.kql) | update to existing rule | medium |

## [#6608](https://github.com/SigmaHQ/sigma/pull/6608) new: HackTool - GodPotato Execution

| Rule | Change | Level |
|---|---|---|
| [HackTool - GodPotato Execution](pr-6608/rules/windows/process_creation/proc_creation_win_hktl_godpotato.kql) | new rule | high |

## [#6605](https://github.com/SigmaHQ/sigma/pull/6605) New rule: Potential Systemd Credential Exposure Via Temporary Directory

| Rule | Change | Level |
|---|---|---|
| [Potential Systemd Credential Exposure Via Temporary Directory](pr-6605/rules/linux/process_creation/proc_creation_lnx_systemd_creds_decrypt_tmp.kql) | new rule | medium |

## [#6600](https://github.com/SigmaHQ/sigma/pull/6600) fix: dead values in LiveKD, dead drop resolver and malicious cmdlet rules

| Rule | Change | Level |
|---|---|---|
| [LiveKD Driver Creation](pr-6600/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver.kql) | update to existing rule | medium |
| [LiveKD Driver Creation By Uncommon Process](pr-6600/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver_susp_creation.kql) | update to existing rule | high |
| [New Connection Initiated To Potential Dead Drop Resolver Domain](pr-6600/rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.kql) | update to existing rule | high |
| [Malicious PowerShell Commandlets - ProcessCreation](pr-6600/rules/windows/process_creation/proc_creation_win_powershell_malicious_cmdlets.kql) | update to existing rule | high |

## [#6597](https://github.com/SigmaHQ/sigma/pull/6597) fix: Potentially Suspicious PowerShell Child Processes - remove dead wmic filter value

| Rule | Change | Level |
|---|---|---|
| [Potentially Suspicious PowerShell Child Processes](pr-6597/rules-threat-hunting/windows/process_creation/proc_creation_win_powershell_susp_child_processes.kql) | update to existing rule | medium |

## [#6595](https://github.com/SigmaHQ/sigma/pull/6595) Add detection rules for T1564.007 VBA Stomping

| Rule | Change | Level |
|---|---|---|
| [Suspicious VbaProject.Bin File Creation](pr-6595/rules/windows/file/file_event/file_event_win_susp_vba_project_creation.kql) | new rule | medium |
| [HackTool - EvilClippy Execution](pr-6595/rules/windows/process_creation/proc_creation_win_hktl_evilclippy.kql) | new rule | high |

## [#6592](https://github.com/SigmaHQ/sigma/pull/6592) New rule: Potential Data Exfiltration To Chat Service Webhook Via CommandLine

| Rule | Change | Level |
|---|---|---|
| [Potential Data Exfiltration To Chat Service Webhook Via CommandLine](pr-6592/rules/windows/process_creation/proc_creation_win_susp_chat_webhook_exfiltration.kql) | new rule | medium |

## [#6589](https://github.com/SigmaHQ/sigma/pull/6589) New rule: Potential Process Masquerading via Invisible Zero-Width Unicode in Image Path

| Rule | Change | Level |
|---|---|---|
| [Potential Process Masquerading via Invisible Zero-Width Unicode in Image Path](pr-6589/rules/windows/process_creation/proc_creation_win_susp_image_zero_width_unicode.kql) | new rule | medium |

## [#6588](https://github.com/SigmaHQ/sigma/pull/6588) New rule: Potential Driver Signature Enforcement Weakening Via Bcdedit.EXE

| Rule | Change | Level |
|---|---|---|
| [Potential Driver Signature Enforcement Weakening Via Bcdedit.EXE](pr-6588/rules/windows/process_creation/proc_creation_win_bcdedit_disable_driver_signature_enforcement.kql) | new rule | medium |

## [#6587](https://github.com/SigmaHQ/sigma/pull/6587) New rule: Potential Print Processor DLL Registration Via Registry

| Rule | Change | Level |
|---|---|---|
| [Potential Print Processor DLL Registration Via Registry](pr-6587/rules/windows/registry/registry_set/registry_set_persistence_print_processor.kql) | new rule | medium |

## [#6586](https://github.com/SigmaHQ/sigma/pull/6586) new: Ntprint.EXE Execution From Non-Default Location

| Rule | Change | Level |
|---|---|---|
| [Ntprint.EXE Execution From Non-Default Location](pr-6586/rules/windows/process_creation/proc_creation_win_ntprint_execution_non_default_location.kql) | new rule | high |

## [#6584](https://github.com/SigmaHQ/sigma/pull/6584) new: Fake Plugin Catalogue Campaign Indicators (PluginDex, AnyPlugins)

| Rule | Change | Level |
|---|---|---|
| [Fake Plugin Catalogue - AutoIt3 Interpreter Started By gVim](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/proc_creation_win_malware_fake_plugin_autoit3_spawned_by_gvim.kql) | new rule | high |
| [Fake Plugin Catalogue - AutoIt3 Interpreter Starting Itself Without Script](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/proc_creation_win_malware_fake_plugin_autoit3_spawns_autoit3_no_args.kql) | new rule | medium |
| [Fake Plugin Catalogue - Chrome Started By AutoIt3 Interpreter](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/proc_creation_win_malware_fake_plugin_autoit3_spawns_chrome.kql) | new rule | medium |
| [Fake Plugin Catalogue - Defender Exclusion On Fake ProgramData Windows Folder](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/proc_creation_win_malware_fake_plugin_defender_exclusion_fake_programdata.kql) | new rule | high |
| [Fake Plugin Catalogue - Deno Evaluating Base64 Decoded Code](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/proc_creation_win_malware_fake_plugin_deno_eval_atob.kql) | new rule | medium |
| [Fake Plugin Catalogue - WinGup Updater Spawning PowerShell Defender Exclusion](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/proc_creation_win_malware_fake_plugin_wingup_defender_exclusion.kql) | new rule | high |
| [Fake Plugin Catalogue - Value System Set Under HKCU EventSystem Key](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/registry_set_malware_fake_plugin_eventsystem_system_value.kql) | new rule | medium |
| [Fake Plugin Catalogue - Run Key Value Launching Deno Eval](pr-6584/rules-emerging-threats/2026/Malware/Fake-Plugin-Catalogues/registry_set_malware_fake_plugin_run_key_deno_eval.kql) | new rule | high |

## [#6581](https://github.com/SigmaHQ/sigma/pull/6581) Add AD CS / ESC coverage-gap detections (14 rules)

| Rule | Change | Level |
|---|---|---|
| [Suspicious ADCS CA Configuration Weakened Via Certutil.EXE](pr-6581/rules/windows/process_creation/proc_creation_win_certutil_adcs_insecure_ca_config.kql) | new rule | high |
| [Potential ADCS CA Security Configuration Tampering](pr-6581/rules/windows/registry/registry_set/registry_set_adcs_ca_policy_flags_modified.kql) | new rule | medium |
| [Suspicious Weak Certificate Mapping Enabled On Domain Controller](pr-6581/rules/windows/registry/registry_set/registry_set_dc_weak_certificate_mapping.kql) | new rule | high |

## [#6578](https://github.com/SigmaHQ/sigma/pull/6578) chore: workflow - update pySigma-validators-sigmahq to 0.30

| Rule | Change | Level |
|---|---|---|
| [TanStack Supply-Chain Attack Execution Indicators - Linux](pr-6578/rules-emerging-threats/2026/Malware/TanStack-Supply-Chain/proc_creation_lnx_malware_tanstack_supply_chain.kql) | update to existing rule | high |
| [TanStack Supply-Chain Attack Execution Indicators - Windows](pr-6578/rules-emerging-threats/2026/Malware/TanStack-Supply-Chain/proc_creation_win_malware_tanstack_supply_chain.kql) | update to existing rule | high |
| [Terminate Linux Process Via Kill](pr-6578/rules-threat-hunting/linux/process_creation/proc_creation_lnx_susp_process_termination_via_kill.kql) | update to existing rule | medium |
| [Group Has Been Deleted Via Groupdel](pr-6578/rules/linux/process_creation/proc_creation_lnx_groupdel.kql) | update to existing rule | medium |
| [HackTool - Mimikatz Kirbi File Creation](pr-6578/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.kql) | update to existing rule | critical |
| [Suspicious Non-Browser Network Communication With Google API](pr-6578/rules/windows/network_connection/net_connection_win_domain_google_api_non_browser_access.kql) | update to existing rule | medium |
| [Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE](pr-6578/rules/windows/process_creation/proc_creation_win_atbroker_uncommon_ats_execution.kql) | update to existing rule | medium |
| [Audit Policy Tampering Via NT Resource Kit Auditpol](pr-6578/rules/windows/process_creation/proc_creation_win_auditpol_nt_resource_kit_usage.kql) | update to existing rule | high |
| [Audit Policy Tampering Via Auditpol](pr-6578/rules/windows/process_creation/proc_creation_win_auditpol_susp_execution.kql) | update to existing rule | high |
| [Cmd Launched with Hidden Start Flags to Suspicious Targets](pr-6578/rules/windows/process_creation/proc_creation_win_cmd_launched_with_hidden_start_flag.kql) | update to existing rule | medium |
| [Suspicious Ping/Del Command Combination](pr-6578/rules/windows/process_creation/proc_creation_win_cmd_ping_del_combined_execution.kql) | update to existing rule | high |
| [HackTool - Hydra Password Bruteforce Execution](pr-6578/rules/windows/process_creation/proc_creation_win_hktl_hydra.kql) | update to existing rule | high |
| [Invoke-Obfuscation CLIP+ Launcher](pr-6578/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_clip.kql) | update to existing rule | high |
| [Invoke-Obfuscation STDIN+ Launcher](pr-6578/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_stdin.kql) | update to existing rule | high |
| [Attempts of Kerberos Coercion Via DNS SPN Spoofing](pr-6578/rules/windows/process_creation/proc_creation_win_kerberos_coercion_via_dns_spn_spoofing.kql) | update to existing rule | high |
| [Obfuscated PowerShell MSI Install via WindowsInstaller COM](pr-6578/rules/windows/process_creation/proc_creation_win_powershell_comobject_msi.kql) | update to existing rule | high |
| [Disable Windows Defender AV Security Monitoring](pr-6578/rules/windows/process_creation/proc_creation_win_powershell_disable_defender_av_security_monitoring.kql) | update to existing rule | high |
| [PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE](pr-6578/rules/windows/process_creation/proc_creation_win_pua_adfind_enumeration.kql) | update to existing rule | high |
| [PUA - AdFind Suspicious Execution](pr-6578/rules/windows/process_creation/proc_creation_win_pua_adfind_susp_usage.kql) | update to existing rule | high |
| [PUA - Memory Dump Mount Via MemProcFS](pr-6578/rules/windows/process_creation/proc_creation_win_pua_memprocfs.kql) | update to existing rule | high |
| [Disabling Windows Defender WMI Autologger Session via Reg.exe](pr-6578/rules/windows/process_creation/proc_creation_win_reg_disable_defender_wmi_autologger.kql) | update to existing rule | high |
| [Bad Opsec Defaults Sacrificial Processes With Improper Arguments](pr-6578/rules/windows/process_creation/proc_creation_win_susp_bad_opsec_sacrificial_processes.kql) | update to existing rule | high |
| [Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix](pr-6578/rules/windows/process_creation/proc_creation_win_susp_clickfix_filefix_whitespace_padding.kql) | update to existing rule | high |
| [Taskkill Symantec Endpoint Protection](pr-6578/rules/windows/process_creation/proc_creation_win_taskkill_sep.kql) | update to existing rule | high |
| [Suspicious Vsls-Agent Command With AgentExtensionPath Load](pr-6578/rules/windows/process_creation/proc_creation_win_vslsagent_agentextensionpath_load.kql) | update to existing rule | medium |
| [Suspicious Space Characters in RunMRU Registry Path - ClickFix](pr-6578/rules/windows/registry/registry_set/registry_set_susp_runmru_space_character.kql) | update to existing rule | high |
| [Suspicious Shell Open Command Registry Modification](pr-6578/rules/windows/registry/registry_set/registry_set_susp_shell_open_keys_modification_patterns.kql) | update to existing rule | medium |
| [Suspicious Space Characters in TypedPaths Registry Path - FileFix](pr-6578/rules/windows/registry/registry_set/registry_set_susp_typedpaths_space_characters.kql) | update to existing rule | high |

## [#6577](https://github.com/SigmaHQ/sigma/pull/6577) Fix three rules with conditions that can never match

| Rule | Change | Level |
|---|---|---|
| [Apache Spark Shell Command Injection - ProcessCreation](pr-6577/rules-emerging-threats/2022/Exploits/CVE-2022-33891/proc_creation_lnx_exploit_cve_2022_33891_spark_shell_command_injection.kql) | update to existing rule | high |
| [Suspicious Regsvr32 Execution From Remote Share](pr-6577/rules/windows/process_creation/proc_creation_win_regsvr32_remote_share.kql) | update to existing rule | high |
| [Removal of Potential COM Hijacking Registry Keys](pr-6577/rules/windows/registry/registry_delete/registry_delete_removal_com_hijacking_registry_key.kql) | update to existing rule | medium |

## [#6574](https://github.com/SigmaHQ/sigma/pull/6574) chore: add regression test for Suspicious Eventlog Clearing or Configuration Change Activity

| Rule | Change | Level |
|---|---|---|
| [Suspicious Eventlog Clearing or Configuration Change Activity](pr-6574/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.kql) | update to existing rule | high |

## [#6568](https://github.com/SigmaHQ/sigma/pull/6568) Add Contagious Interview TCP Backdoor Rules

| Rule | Change | Level |
|---|---|---|
| [Contagious Interview TCP Backdoor Lock File Creation](pr-6568/rules-emerging-threats/2026/TA/Contagious-Interview/file_event_win_mal_contagious_interview_tcp_backdoor_lock_file.kql) | new rule | high |
| [Contagious Interview TCP Backdoor Detached Command Execution](pr-6568/rules-emerging-threats/2026/TA/Contagious-Interview/proc_creation_win_mal_contagious_interview_tcp_backdoor_exec.kql) | new rule | medium |

## [#6566](https://github.com/SigmaHQ/sigma/pull/6566) fix: office installation false positives

| Rule | Change | Level |
|---|---|---|
| [Wow6432Node CurrentVersion Autorun Keys Modification](pr-6566/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node.kql) | update to existing rule | medium |

## [#6564](https://github.com/SigmaHQ/sigma/pull/6564) New rules for AI coding agent CLI abuse (Claude Code, Codex CLI)

| Rule | Change | Level |
|---|---|---|
| [AI Coding Agent Settings File Created By Uncommon Process](pr-6564/rules/windows/file/file_event/file_event_win_ai_agent_config_created_by_uncommon_process.kql) | new rule | medium |
| [AI Coding Agent CLI Execution With Permission or Sandbox Bypass](pr-6564/rules/windows/process_creation/proc_creation_win_ai_agent_cli_permission_bypass.kql) | new rule | medium |
| [Scheduled Task Creation Running AI Coding Agent CLI](pr-6564/rules/windows/process_creation/proc_creation_win_schtasks_create_ai_agent_cli.kql) | new rule | medium |

## [#6557](https://github.com/SigmaHQ/sigma/pull/6557) Add Entroprism AIP self-built detection rules (6 rules)

| Rule | Change | Level |
|---|---|---|
| [AMSI Bypass (patch amsi.dll AmsiScanBuffer / reflection unload)](pr-6557/rules/windows/process_creation/amsi_bypass_patch_amsi.dll_amsiscanbuffer__reflection_unload.kql) | new rule | high |
| [ETW Tampering (disable event tracing / unhook ntdll)](pr-6557/rules/windows/process_creation/etw_tampering_disable_event_tracing__unhook_ntdll.kql) | new rule | high |
| [Sandbox / Virtualization Environment Detection](pr-6557/rules/windows/process_creation/sandbox__virtualization_environment_detection.kql) | new rule | medium |

## [#6543](https://github.com/SigmaHQ/sigma/pull/6543) Update macOS launchctl rule to cover the bootstrap verb

| Rule | Change | Level |
|---|---|---|
| [Launch Agent/Daemon Execution Via Launchctl](pr-6543/rules/macos/process_creation/proc_creation_macos_launchctl_execution.kql) | update to existing rule | medium |

## [#6542](https://github.com/SigmaHQ/sigma/pull/6542) Add Linux rule: Potential Shell Or Command Execution Via Tar

| Rule | Change | Level |
|---|---|---|
| [Suspicious Child Process Spawned By Tar](pr-6542/rules/linux/process_creation/proc_creation_lnx_susp_tar_children.kql) | new rule | high |
| [Command Execution Attempt via Tar - Linux](pr-6542/rules/linux/process_creation/proc_creation_lnx_tar_cmd_execution.kql) | new rule | medium |

## [#6540](https://github.com/SigmaHQ/sigma/pull/6540) Sigma: PavinLoader fake-driver MSI campaign (MSBuild from %LOCALAPPDATA%, MSBUILDENABLEALLPROPERTYFUNCTIONS, fake dllhost/taskhostw tasks, m

| Rule | Change | Level |
|---|---|---|
| [Scheduled Task Files Masquerading as System Binaries (dllhost/taskhostw)](pr-6540/rules/windows/file_event/file_event_win_schtask_files_dllhost_taskhostw.kql) | new rule | high |
| [cmd.exe Command Line Referencing the MSBuild Property-Function Escape Variable](pr-6540/rules/windows/process_creation/proc_creation_win_cmd_msbuildenableallpropertyfunctions.kql) | new rule | high |
| [MSBuild.exe Execution from User-Writable Directory via cmd.exe](pr-6540/rules/windows/process_creation/proc_creation_win_msbuild_user_writable_path_cmd_parent.kql) | new rule | medium |
| [msiexec.exe Spawning cmd.exe to Start an LNK File](pr-6540/rules/windows/process_creation/proc_creation_win_msiexec_spawns_cmd_start_lnk.kql) | new rule | high |

## [#6538](https://github.com/SigmaHQ/sigma/pull/6538) New Rule: Potential Ingress Tool Transfer Via ECMangen.EXE

| Rule | Change | Level |
|---|---|---|
| [Potential Ingress Tool Transfer Via ECMangen.EXE](pr-6538/rules/windows/process_creation/proc_creation_win_ecmangen_ingress_tool_transfer.kql) | new rule | medium |

## [#6537](https://github.com/SigmaHQ/sigma/pull/6537) new: Potential Child Process from Node.js or Bun - Node2Shell (CVE-2026-111497)

| Rule | Change | Level |
|---|---|---|
| [Potential Child Process from Node.js or Bun - Node2Shell - Linux](pr-6537/rules-emerging-threats/2026/Exploits/CVE-2026-111497/proc_creation_lnx_exploit_cve_2026_111497_node2shell_child_process.kql) | new rule | medium |
| [Potential Child Process from Node.js or Bun - Node2Shell - Windows](pr-6537/rules-emerging-threats/2026/Exploits/CVE-2026-111497/proc_creation_win_exploit_cve_2026_111497_node2shell_child_process.kql) | new rule | medium |

## [#6535](https://github.com/SigmaHQ/sigma/pull/6535) Add Fax service configuration detection and regression tests

| Rule | Change | Level |
|---|---|---|
| [Fax Service Binary Path Modified via Sc.exe](pr-6535/rules/windows/process_creation/proc_creation_win_fax_service_config_sc.kql) | new rule | high |
| [Fax Service ImagePath Modified to PowerShell](pr-6535/rules/windows/registry/registry_set/registry_set_win_fax_service_imagepath_powershell.kql) | new rule | high |

## [#6531](https://github.com/SigmaHQ/sigma/pull/6531) Detect yootheme pro CVE 2026 102785

| Rule | Change | Level |
|---|---|---|
| [YOOtheme Pro Suspicious Webshell Creation](pr-6531/rules/linux/file_event/file_event_lnx_yootheme_pro_webshell_creation.kql) | new rule | high |
| [YOOtheme Pro Webshell Suspicious Command Execution](pr-6531/rules/windows/process_creation/proc_creation_win_webshell_command_execution_yootheme.kql) | new rule | high |

## [#6530](https://github.com/SigmaHQ/sigma/pull/6530) Add rules for proxy execution via Ntsd, PIX and UE-V AppLauncher

| Rule | Change | Level |
|---|---|---|
| [Suspicious Child Process Of Ntsd.EXE](pr-6530/rules/windows/process_creation/proc_creation_win_ntsd_susp_child_process.kql) | new rule | medium |
| [Suspicious Child Process Of PIX Engine Host](pr-6530/rules/windows/process_creation/proc_creation_win_pix_enginehost_susp_child_process.kql) | new rule | medium |
| [Suspicious Child Process Of UE-V AppLauncher](pr-6530/rules/windows/process_creation/proc_creation_win_uev_applauncher_susp_child_process.kql) | new rule | medium |

## [#6529](https://github.com/SigmaHQ/sigma/pull/6529) feat(rules): detect recursive world-writable chmod on system directories

| Rule | Change | Level |
|---|---|---|
| [Chmod Recursive World-Writable Mode on System Directories](pr-6529/rules/linux/process_creation/proc_creation_lnx_chmod_recursive_world_writable_system_dirs.kql) | new rule | high |

## [#6526](https://github.com/SigmaHQ/sigma/pull/6526) fix: Suspicious Rundll32 Execution With Image Extension - filter the WebDAV client (davclnt.dll,DavSetCookie)

| Rule | Change | Level |
|---|---|---|
| [Suspicious Rundll32 Execution With Image Extension](pr-6526/rules/windows/process_creation/proc_creation_win_rundll32_susp_execution_with_image_extension.kql) | update to existing rule | high |

## [#6525](https://github.com/SigmaHQ/sigma/pull/6525) Add detection rules for LiteLLM 1.107.0 cook.pth supply-chain compromise

| Rule | Change | Level |
|---|---|---|
| [Suspicious LiteLLM Python Startup Hook File Creation](pr-6525/rules/windows/file/file_event/file_event_win_litellm_cook_pth_creation.kql) | new rule | high |
| [Python Process Spawning Windows Discovery Utilities](pr-6525/rules/windows/process_creation/proc_creation_win_litellm_python_discovery_utils.kql) | new rule | medium |

## [#6521](https://github.com/SigmaHQ/sigma/pull/6521) fix: Suspicious Run Key from Download - filter installers registering their Program Files app, and key create/delete events

| Rule | Change | Level |
|---|---|---|
| [Suspicious Run Key from Download](pr-6521/rules/windows/registry/registry_event/registry_event_susp_download_run_key.kql) | update to existing rule | high |

## [#6519](https://github.com/SigmaHQ/sigma/pull/6519) new: Systemd Generator Created

| Rule | Change | Level |
|---|---|---|
| [Systemd Generator Created](pr-6519/rules/linux/file_event/file_event_lnx_persistence_systemd_generator_created.kql) | new rule | medium |

## [#6512](https://github.com/SigmaHQ/sigma/pull/6512) feat: add rule for .NET add-in pipeline host execution (AddInProcess/AddInUtil LOLBins)

| Rule | Change | Level |
|---|---|---|
| [DotNet Add-In Pipeline Host Execution](pr-6512/rules/windows/process_creation/proc_creation_win_lolbin_addinpipeline.kql) | new rule | medium |

## [#6508](https://github.com/SigmaHQ/sigma/pull/6508) Add Windows rules for T1547.012 Print Processors persistence

| Rule | Change | Level |
|---|---|---|
| [Drop Binaries Into Print Processor Directory](pr-6508/rules/windows/file/file_event/file_event_win_susp_print_processor_folder_drop.kql) | new rule | high |
| [Potential Print Processor Persistence Via Registry](pr-6508/rules/windows/registry/registry_set/registry_set_win_print_processor_persistence.kql) | new rule | high |

## [#6506](https://github.com/SigmaHQ/sigma/pull/6506) new: Add php2shell (CVE-2026-109618/9) detection rules and update existing webshell coverage

| Rule | Change | Level |
|---|---|---|
| [Linux Webshell Indicators](pr-6506/rules/linux/process_creation/proc_creation_lnx_webshell_detection.kql) | update to existing rule | high |
| [Webshell Hacking Activity Patterns](pr-6506/rules/windows/process_creation/proc_creation_win_webshell_hacking.kql) | update to existing rule | high |
| [Webshell Detection With Command Line Keywords](pr-6506/rules/windows/process_creation/proc_creation_win_webshell_recon_commands_and_processes.kql) | update to existing rule | high |
| [Suspicious Process By Web Server Process](pr-6506/rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.kql) | update to existing rule | high |
| [Webshell Tool Reconnaissance Activity](pr-6506/rules/windows/process_creation/proc_creation_win_webshell_tool_recon.kql) | update to existing rule | high |

## [#6503](https://github.com/SigmaHQ/sigma/pull/6503) new: LiteLLM PyPI Compromise Indicators (1.107.0)

| Rule | Change | Level |
|---|---|---|
| [LiteLLM PyPI Compromise File Creation Indicators - Linux](pr-6503/rules-emerging-threats/2026/Malware/LiteLLM-PyPI-Compromise/file_event_lnx_malware_litellm_pypi_compromise.kql) | new rule | high |
| [LiteLLM PyPI Compromise File Creation Indicators - MacOS](pr-6503/rules-emerging-threats/2026/Malware/LiteLLM-PyPI-Compromise/file_event_macos_malware_litellm_pypi_compromise.kql) | new rule | high |
| [LiteLLM PyPI Compromise File Creation Indicators - Windows](pr-6503/rules-emerging-threats/2026/Malware/LiteLLM-PyPI-Compromise/file_event_win_malware_litellm_pypi_compromise.kql) | new rule | high |

## [#6502](https://github.com/SigmaHQ/sigma/pull/6502) Add Radmin DLL sideloading detection rule

| Rule | Change | Level |
|---|---|---|
| [Potential Radmin DLL Sideloading From User AppData](pr-6502/rules/windows/image_load/image_load_side_load_radmin_dll.kql) | new rule | high |

## [#6500](https://github.com/SigmaHQ/sigma/pull/6500) new: Contagious Interview (DPRK) EtherHiding Chain - Emerging Threat And Hunting Rules

| Rule | Change | Level |
|---|---|---|
| [Contagious Interview Loader Artefacts Or Persistence Created - MacOS](pr-6500/rules-emerging-threats/2026/TA/Contagious-Interview/file_event_macos_mal_contagious_interview_vs_cache_artefacts.kql) | new rule | high |
| [NetSupport Client Dropped Into SettingSync ResCache Masquerade Path](pr-6500/rules-emerging-threats/2026/TA/Contagious-Interview/file_event_win_mal_contagious_interview_netsupport_settingsync.kql) | new rule | high |
| [Contagious Interview Loader Artefacts Created In User .vs_cache Folder - Windows](pr-6500/rules-emerging-threats/2026/TA/Contagious-Interview/file_event_win_mal_contagious_interview_vs_cache_artefacts.kql) | new rule | high |
| [Contagious Interview Implant Run Key Persistence](pr-6500/rules-emerging-threats/2026/TA/Contagious-Interview/registry_set_mal_contagious_interview_run_key_persistence.kql) | new rule | high |

## [#6495](https://github.com/SigmaHQ/sigma/pull/6495) Fix `Apache Spark Shell Command Injection` rules - bash Image filter and CVE number

| Rule | Change | Level |
|---|---|---|
| [Apache Spark Shell Command Injection - ProcessCreation](pr-6495/rules-emerging-threats/2022/Exploits/CVE-2022-33891/proc_creation_lnx_exploit_cve_2022_33891_spark_shell_command_injection.kql) | update to existing rule | high |

## [#6494](https://github.com/SigmaHQ/sigma/pull/6494) fix: CMSTP App Paths Registry Key Modification and Uncommon Svchost Parent Process FPs

| Rule | Change | Level |
|---|---|---|
| [Uncommon Svchost Parent Process](pr-6494/rules/windows/process_creation/proc_creation_win_svchost_uncommon_parent_process.kql) | update to existing rule | medium |
| [CMSTP App Paths Registry Key Modification](pr-6494/rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.kql) | update to existing rule | high |

## [#6484](https://github.com/SigmaHQ/sigma/pull/6484) new: ClickFix Operation String in Registry

| Rule | Change | Level |
|---|---|---|
| [ClickFix File Operation](pr-6484/rules/windows/registry/registry_set/registry_set_clickfix_op.kql) | new rule | medium |

## [#6479](https://github.com/SigmaHQ/sigma/pull/6479) new: Nsenter Escape to Host Namespace (T1611)

| Rule | Change | Level |
|---|---|---|
| [Nsenter Escape to Host Namespace](pr-6479/rules/linux/process_creation/proc_creation_lnx_nsenter_container_escape.kql) | new rule | high |

## [#6476](https://github.com/SigmaHQ/sigma/pull/6476) Add SLAPSHOT/WHIPSHOT implant detection rules for CVE-2026-88771/88772

| Rule | Change | Level |
|---|---|---|
| [SLAPSHOT/WHIPSHOT Implant File Creation](pr-6476/rules-emerging-threats/2026/Exploits/SLAPSHOT-WHIPSHOT/lnx_file_slapshot_whipshot_implant_file_creation.kql) | new rule | critical |
| [SLAPSHOT Agent and Bridge Component Execution](pr-6476/rules-emerging-threats/2026/Exploits/SLAPSHOT-WHIPSHOT/lnx_proc_slapshot_whipshot_agent_execution.kql) | new rule | high |

## [#6474](https://github.com/SigmaHQ/sigma/pull/6474) new: AOMEI Backupper supply chain compromise rules

| Rule | Change | Level |
|---|---|---|
| [Suspicious Executable Created In AOMEI Backupper Tmphtml Directory](pr-6474/rules/windows/file/file_event/file_event_win_aomei_backupper_susp_exe_in_tmphtml.kql) | new rule | high |
| [Suspicious AOMEI ABNotify Child Process From Html Directory](pr-6474/rules/windows/process_creation/proc_creation_win_aomei_abnotify_susp_child_from_html_dir.kql) | new rule | high |

## [#6470](https://github.com/SigmaHQ/sigma/pull/6470) fix: HackTool - CrackMapExec File Indicators - anchor output-file regexes to the Temp root

| Rule | Change | Level |
|---|---|---|
| [HackTool - CrackMapExec File Indicators](pr-6470/rules/windows/file/file_event/file_event_win_hktl_crackmapexec_indicators.kql) | update to existing rule | high |

## [#6464](https://github.com/SigmaHQ/sigma/pull/6464) feat(windows): detect potential Veeam credential access via psql.exe

| Rule | Change | Level |
|---|---|---|
| [Potential Veeam PostgreSQL Credential Table Query Via Psql.EXE](pr-6464/rules/windows/process_creation/proc_creation_win_psql_veeam_credential_query.kql) | new rule | medium |

## [#6459](https://github.com/SigmaHQ/sigma/pull/6459) new: COM TypeLib hijack via scriptlet moniker + script runtime loaded by Explorer

| Rule | Change | Level |
|---|---|---|
| [Windows Script Host Or Scriptlet Runtime Loaded By Explorer](pr-6459/rules/windows/image_load/image_load_explorer_script_runtime_load.kql) | new rule | high |
| [COM TypeLib Hijack Via Scriptlet Or Remote Moniker](pr-6459/rules/windows/registry/registry_set/registry_set_persistence_typelib_script_moniker.kql) | new rule | high |

## [#6456](https://github.com/SigmaHQ/sigma/pull/6456) new: Potential Launch Agent/Daemon Masquerading As Apple

| Rule | Change | Level |
|---|---|---|
| [Potential Launch Agent/Daemon Masquerading As Apple](pr-6456/rules/macos/file_event/file_event_macos_launch_item_masquerading_as_apple.kql) | new rule | medium |

## [#6452](https://github.com/SigmaHQ/sigma/pull/6452) Add Azazel ransom note creation rule for Linux

| Rule | Change | Level |
|---|---|---|
| [Azazel Ransom Note Creation - Linux](pr-6452/rules-emerging-threats/2026/TA/Azazel/file_event_lnx_azazel_ransom_note.kql) | new rule | high |

## [#6451](https://github.com/SigmaHQ/sigma/pull/6451) Add macOS encoded payload piped to shell rule

| Rule | Change | Level |
|---|---|---|
| [Suspicious Encoded Payload Piped To Shell - macOS](pr-6451/rules/macos/process_creation/proc_creation_macos_susp_encoded_payload_piped_to_shell.kql) | new rule | medium |

## [#6450](https://github.com/SigmaHQ/sigma/pull/6450) Expand macOS keychain credential access coverage

| Rule | Change | Level |
|---|---|---|
| [Credentials from Password Stores - Keychain](pr-6450/rules/macos/process_creation/proc_creation_macos_creds_from_keychain.kql) | update to existing rule | medium |

## [#6449](https://github.com/SigmaHQ/sigma/pull/6449) Add macOS browser credential and cookie store access rule

| Rule | Change | Level |
|---|---|---|
| [Potential Browser Credential and Cookie Store Access - macOS](pr-6449/rules/macos/process_creation/proc_creation_macos_browser_credential_store_access.kql) | new rule | medium |

## [#6444](https://github.com/SigmaHQ/sigma/pull/6444) new: papercut exploitation rules for CVE-2026-81578 and CVE-2026-82078

| Rule | Change | Level |
|---|---|---|
| [PaperCut MF/NG Potential Exploitation for Arbitrary Code Execution](pr-6444/rules-emerging-threats/2023/TA/PaperCut-Print-Management-Exploitation/proc_creation_win_papercut_print_management_exploitation_pc_app.kql) | update to existing rule | high |
| [Potential PaperCut NG/MF Tapestry Page Webshell Plant - Linux](pr-6444/rules-emerging-threats/2026/Exploits/CVE-2026-81578/file_event_lnx_exploit_cve_2026_81578_papercut_tapestry_webshell_plant.kql) | new rule | medium |
| [Suspicious PaperCut Class File Drop in Server Lib - Linux](pr-6444/rules-emerging-threats/2026/Exploits/CVE-2026-81578/file_event_lnx_exploit_cve_2026_82078_susp_class_drop.kql) | new rule | medium |
| [Potential PaperCut NG/MF Tapestry Page Webshell Plant](pr-6444/rules-emerging-threats/2026/Exploits/CVE-2026-81578/file_event_win_exploit_cve_2026_81578_papercut_tapestry_webshell_plant.kql) | new rule | medium |
| [Suspicious PaperCut Class File Drop in Server Lib - Windows](pr-6444/rules-emerging-threats/2026/Exploits/CVE-2026-81578/file_event_win_exploit_cve_2026_82078_susp_class_drop.kql) | new rule | medium |
| [Suspicious Child Process Spawned by PaperCut Application Server](pr-6444/rules-emerging-threats/2026/Exploits/CVE-2026-81578/proc_creation_lnx_exploit_cve_2026_81578_papercut_susp_child_process.kql) | new rule | high |

## [#6443](https://github.com/SigmaHQ/sigma/pull/6443) Detection vstest susp location

| Rule | Change | Level |
|---|---|---|
| [Potential Proxy Execution Via VSTest From Suspicious Location](pr-6443/rules/windows/process_creation/proc_creation_win_vstest_susp_location.kql) | new rule | medium |

## [#6438](https://github.com/SigmaHQ/sigma/pull/6438) Add Linux rule: Potential Shell Or Command Execution Via Xargs

| Rule | Change | Level |
|---|---|---|
| [Potential Shell Or Command Execution Via Xargs](pr-6438/rules/linux/process_creation/proc_creation_lnx_xargs_shell_execution.kql) | new rule | high |

## [#6437](https://github.com/SigmaHQ/sigma/pull/6437) Add Linux rule: Potential Shell Or Command Execution Via GDB

| Rule | Change | Level |
|---|---|---|
| [Potential Shell Or Command Execution Via GDB](pr-6437/rules/linux/process_creation/proc_creation_lnx_gdb_shell_execution.kql) | new rule | high |

## [#6436](https://github.com/SigmaHQ/sigma/pull/6436) Add Linux rule: Potential Command Execution Via Tcpdump Postrotate Command

| Rule | Change | Level |
|---|---|---|
| [Potential Command Execution Via Tcpdump Postrotate Command](pr-6436/rules/linux/process_creation/proc_creation_lnx_tcpdump_postrotate_command.kql) | new rule | high |

## [#6435](https://github.com/SigmaHQ/sigma/pull/6435) Add Linux rule: Potential Command Execution Via Tar Checkpoint Or To-Command

| Rule | Change | Level |
|---|---|---|
| [Potential Command Execution Via Tar Checkpoint Or To-Command](pr-6435/rules/linux/process_creation/proc_creation_lnx_tar_command_execution.kql) | new rule | high |

## [#6434](https://github.com/SigmaHQ/sigma/pull/6434) Add Linux rule: Potential Execution Or Persistence Via Systemd-Run

| Rule | Change | Level |
|---|---|---|
| [Potential Execution Or Persistence Via Systemd-Run](pr-6434/rules/linux/process_creation/proc_creation_lnx_susp_systemd_run_execution.kql) | new rule | medium |

## [#6429](https://github.com/SigmaHQ/sigma/pull/6429) Add rule: suspicious shadow file access via standard utilities

| Rule | Change | Level |
|---|---|---|
| [Suspicious Shadow File Access via Standard Utilities](pr-6429/rules/linux/process_creation/proc_creation_lnx_susp_shadow_access.kql) | new rule | medium |

## [#6426](https://github.com/SigmaHQ/sigma/pull/6426) New Rule: Suspicious Child Process Spawned By IntelliTrace.EXE

| Rule | Change | Level |
|---|---|---|
| [Suspicious Child Process Spawned By IntelliTrace.EXE](pr-6426/rules/windows/process_creation/proc_creation_win_intellitrace_susp_child.kql) | new rule | medium |

## [#6425](https://github.com/SigmaHQ/sigma/pull/6425) CredUI.DLL Loaded By Uncommon Process - add Spotify filter

| Rule | Change | Level |
|---|---|---|
| [CredUI.DLL Loaded By Uncommon Process](pr-6425/rules/windows/image_load/image_load_dll_credui_uncommon_process_load.kql) | update to existing rule | medium |

## [#6424](https://github.com/SigmaHQ/sigma/pull/6424) fix: Remote Access Tool - ScreenConnect Installation Execution - remove optional '&c=' parameter

| Rule | Change | Level |
|---|---|---|
| [Remote Access Tool - ScreenConnect Installation Execution](pr-6424/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_installation_cli_param.kql) | update to existing rule | medium |

## [#6423](https://github.com/SigmaHQ/sigma/pull/6423) Remote File Download Via Xsd.EXE

| Rule | Change | Level |
|---|---|---|
| [Remote File Download Via Xsd.EXE](pr-6423/rules/windows/process_creation/proc_creation_win_xsd_remote_download.kql) | new rule | medium |

## [#6422](https://github.com/SigmaHQ/sigma/pull/6422) New Rule: Potentially Suspicious Child Process Of VSLaunchBrowser

| Rule | Change | Level |
|---|---|---|
| [Potentially Suspicious Child Process Of VSLaunchBrowser](pr-6422/rules/windows/process_creation/proc_creation_win_vslaunchbrowser_susp_child.kql) | new rule | medium |

## [#6419](https://github.com/SigmaHQ/sigma/pull/6419) Detection testwindowremoteagent uncommon location

| Rule | Change | Level |
|---|---|---|
| [Potentially Suspicious TestWindowRemoteAgent Execution From Uncommon Location](pr-6419/rules/windows/process_creation/proc_creation_win_testwindowremoteagent_uncommon_location.kql) | new rule | medium |

## [#6418](https://github.com/SigmaHQ/sigma/pull/6418) Detection texttransform suspicious child

| Rule | Change | Level |
|---|---|---|
| [Potentially Suspicious Child Process Of TextTransform](pr-6418/rules/windows/process_creation/proc_creation_win_texttransform_susp_child_process.kql) | new rule | medium |

## [#6416](https://github.com/SigmaHQ/sigma/pull/6416) Add restore point disable and PS history clearing rules; expand service tamper coverage

| Rule | Change | Level |
|---|---|---|
| [Clear PowerShell History via CommandLine](pr-6416/rules/windows/process_creation/proc_creation_win_powershell_clear_history.kql) | new rule | medium |
| [System Restore Point Disabling or Removal Attempt via PowerShell](pr-6416/rules/windows/process_creation/proc_creation_win_powershell_restore_point_disable.kql) | new rule | medium |
| [Suspicious Windows Service Tampering](pr-6416/rules/windows/process_creation/proc_creation_win_susp_service_tamper.kql) | update to existing rule | high |

## [#6362](https://github.com/SigmaHQ/sigma/pull/6362) new: TCC Permissions Reset Via Tccutil

| Rule | Change | Level |
|---|---|---|
| [TCC Permissions Reset Via Tccutil](pr-6362/rules/macos/process_creation/proc_creation_macos_tccutil_reset_permissions.kql) | new rule | medium |

## [#6359](https://github.com/SigmaHQ/sigma/pull/6359) new: add self-deletion via choice/del command combination

| Rule | Change | Level |
|---|---|---|
| [Potential Self-Deletion Via Choice/Del Command Combination](pr-6359/rules/windows/process_creation/proc_creation_win_cmd_choice_del_combined_execution.kql) | new rule | medium |

## [#6358](https://github.com/SigmaHQ/sigma/pull/6358) Detection wslc host mount shell

| Rule | Change | Level |
|---|---|---|
| [Potentially Suspicious WSLC Host Directory Mount With Shell](pr-6358/rules/windows/process_creation/proc_creation_win_wslc_susp_host_mount_shell.kql) | new rule | medium |

## [#6357](https://github.com/SigmaHQ/sigma/pull/6357) chore: Move Certighost CDC Chase rules to placeholder and fix script interpreter rule metadat

| Rule | Change | Level |
|---|---|---|
| [Script Interpreter CommandLine With Reference To Suspicious Directory](pr-6357/rules/windows/process_creation/proc_creation_win_script_interpreter_susp_dir_cmdline.kql) | new rule | high |

## [#6356](https://github.com/SigmaHQ/sigma/pull/6356) Add rule: Suspicious Makecab/Diantz File Staging Or Ingress

| Rule | Change | Level |
|---|---|---|
| [Suspicious Makecab/Diantz File Staging Or Ingress](pr-6356/rules/windows/process_creation/proc_creation_win_lolbin_makecab_diantz_sensitive_staging.kql) | new rule | high |

## [#6354](https://github.com/SigmaHQ/sigma/pull/6354) add suspicious IEDiagCmd child process detection

| Rule | Change | Level |
|---|---|---|
| [Suspicious Child Process From IEDiagCmd.EXE](pr-6354/rules/windows/process_creation/proc_creation_win_iediagcmd_susp_child.kql) | new rule | high |

## [#6335](https://github.com/SigmaHQ/sigma/pull/6335) Add OpenAI Codex CLI approval and sandbox bypass detection

| Rule | Change | Level |
|---|---|---|
| [OpenAI Codex CLI Approval and Sandbox Bypass Mode](pr-6335/rules/windows/process_creation/proc_creation_win_codex_approval_sandbox_bypass.kql) | new rule | medium |

## [#6329](https://github.com/SigmaHQ/sigma/pull/6329) Add dotnet-counters proxy execution detection

| Rule | Change | Level |
|---|---|---|
| [Binary Proxy Execution Via Dotnet-Counters.EXE](pr-6329/rules/windows/process_creation/proc_creation_win_dotnet_counters_lolbin_execution.kql) | new rule | medium |

## [#6326](https://github.com/SigmaHQ/sigma/pull/6326) feat(macos): detect MacSync Stealer chunked upload

| Rule | Change | Level |
|---|---|---|
| [MacSync Stealer Chunked Upload Via Curl](pr-6326/rules-emerging-threats/2026/Malware/MacSync-Stealer/proc_creation_macos_malware_macsync_curl_upload.kql) | new rule | high |

## [#6322](https://github.com/SigmaHQ/sigma/pull/6322) Add detection rule for insecure SMBv1 enablement

| Rule | Change | Level |
|---|---|---|
| [Insecure SMBv1 Protocol Enablement](pr-6322/rules/windows/process_creation/proc_creation_win_insecure_smbv1_enablement.kql) | new rule | high |

## [#6320](https://github.com/SigmaHQ/sigma/pull/6320) feat: add Sonoma Stealer (SONOMAC1) macOS detection rules

| Rule | Change | Level |
|---|---|---|
| [Sonoma Stealer Staging File Creation - macOS](pr-6320/rules-emerging-threats/2026/Malware/Sonoma-Stealer/file_event_macos_sonoma_stealer_staging_files.kql) | new rule | high |
| [Sonoma Stealer Staging Script Fetch From C2 - macOS](pr-6320/rules-emerging-threats/2026/Malware/Sonoma-Stealer/proc_creation_macos_sonoma_stealer_agent_script.kql) | new rule | high |
| [Sonoma Stealer Loader Execution Chain - macOS](pr-6320/rules-emerging-threats/2026/Malware/Sonoma-Stealer/proc_creation_macos_sonoma_stealer_loader_chain.kql) | new rule | high |

## [#6319](https://github.com/SigmaHQ/sigma/pull/6319) new: Rundll32 Execution of DLL Masquerading as Non-Executable File Type

| Rule | Change | Level |
|---|---|---|
| [Rundll32 Execution With Module In User-Writable Staging Directory](pr-6319/rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_susp_module_staging_dir.kql) | new rule | medium |
| [Rundll32 Export Call Against Document Or Data File Extension](pr-6319/rules/windows/process_creation/proc_creation_win_rundll32_doc_or_data_extension.kql) | new rule | high |

## [#6316](https://github.com/SigmaHQ/sigma/pull/6316) Add detection rule for containerd systemd hijacking. Tag The Gentlemen.

| Rule | Change | Level |
|---|---|---|
| [Masqueraded Containerd Systemd Hijacking and Shadow X11 Persistence](pr-6316/rules/linux/process_creation/the_gentlemen_containerd_injector.kql) | new rule | critical |

## [#6313](https://github.com/SigmaHQ/sigma/pull/6313) new: Potential Container Escape Via Docker Socket Or Host Namespace Access

| Rule | Change | Level |
|---|---|---|
| [Potential Container Escape Via Docker Socket Or Host Namespace Access](pr-6313/rules/linux/process_creation/proc_creation_lnx_container_host_access_flags.kql) | new rule | medium |

## [#6310](https://github.com/SigmaHQ/sigma/pull/6310) new: Potential BigDiskBuster-Like Buster-File Creation in TEMP

| Rule | Change | Level |
|---|---|---|
| [Potential BigDiskBuster-Like Buster-File Creation in TEMP](pr-6310/rules/windows/file/file_event/file_event_win_bigdiskbuster_temp_file.kql) | new rule | medium |

## [#6308](https://github.com/SigmaHQ/sigma/pull/6308) Add OpenSSH PKCS11Provider DLL load detection

| Rule | Change | Level |
|---|---|---|
| [Potential DLL Execution Via OpenSSH PKCS11Provider](pr-6308/rules/windows/process_creation/proc_creation_win_openssh_pkcs11provider.kql) | new rule | medium |

## [#6307](https://github.com/SigmaHQ/sigma/pull/6307) Add detection for Steam Client Service LPE via BrokenPipe VDF install…

| Rule | Change | Level |
|---|---|---|
| [BrokenPipe - Steam LPE SYSTEM Child Outside Install Directory](pr-6307/rules/windows/process_creation/proc_creation_win_steam_lpe_brokenpipe.kql) | new rule | high |

## [#6306](https://github.com/SigmaHQ/sigma/pull/6306) Add rule for LockScreenContentServer.exe execution from uncommon folders

| Rule | Change | Level |
|---|---|---|
| [LockScreenContentServer Execution From Uncommon Folder](pr-6306/rules/windows/process_creation/proc_creation_win_lockscreencontentserver_uncommon_path.kql) | new rule | high |

## [#6304](https://github.com/SigmaHQ/sigma/pull/6304) new: detect MCP servers launched via npx or uvx

| Rule | Change | Level |
|---|---|---|
| [MCP Server Execution Attempt Via NPX Or UVX](pr-6304/rules/windows/process_creation/proc_creation_win_node_mcp_server_via_npx_or_uvx.kql) | new rule | medium |

## [#6299](https://github.com/SigmaHQ/sigma/pull/6299) fix(rules): account for quoted command lines in bad opsec sacrificial processes

| Rule | Change | Level |
|---|---|---|
| [Bad Opsec Defaults Sacrificial Processes With Improper Arguments](pr-6299/rules/windows/process_creation/proc_creation_win_susp_bad_opsec_sacrificial_processes.kql) | update to existing rule | high |

## [#6293](https://github.com/SigmaHQ/sigma/pull/6293) new: Redis Server Process Writing To SSH Authorized Keys File

| Rule | Change | Level |
|---|---|---|
| [Redis Server Process Writing To SSH Authorized Keys File](pr-6293/rules/linux/file_event/file_event_lnx_redis_authorized_keys_write.kql) | new rule | high |

## [#6285](https://github.com/SigmaHQ/sigma/pull/6285) Add DbgSrv.exe child process detection

| Rule | Change | Level |
|---|---|---|
| [Potential DbgSrv.EXE Abuse](pr-6285/rules/windows/process_creation/proc_creation_win_dbgsrv_child_process.kql) | new rule | medium |

## [#6280](https://github.com/SigmaHQ/sigma/pull/6280) new: PackClient malware detections

| Rule | Change | Level |
|---|---|---|
| [PackClient NvSvc Scheduled Task Creation](pr-6280/rules-emerging-threats/2026/Malware/PackClient/proc_creation_win_malware_packclient_nvsvc_task.kql) | new rule | high |
| [PackClient Screenshot Worker Execution](pr-6280/rules-emerging-threats/2026/Malware/PackClient/proc_creation_win_malware_packclient_screenshot_worker.kql) | new rule | high |

## [#6279](https://github.com/SigmaHQ/sigma/pull/6279) 🩺 add regression data from evtx-attack-samples

| Rule | Change | Level |
|---|---|---|
| [Trickbot Malware Activity](pr-6279/rules-emerging-threats/2020/Malware/Trickbot/proc_creation_win_malware_trickbot_wermgr.kql) | update to existing rule | high |
| [Potential Pikabot Hollowing Activity](pr-6279/rules-emerging-threats/2023/Malware/Pikabot/proc_creation_win_malware_pikabot_rundll32_hollowing.kql) | update to existing rule | high |
| [Pikabot Fake DLL Extension Execution Via Rundll32.EXE](pr-6279/rules-emerging-threats/2023/Malware/Pikabot/proc_creation_win_malware_pikabot_rundll32_uncommon_extension.kql) | update to existing rule | high |
| [Qakbot Rundll32 Fake DLL Extension Execution](pr-6279/rules-emerging-threats/2023/Malware/Qakbot/proc_creation_win_malware_qakbot_rundll32_fake_dll_execution.kql) | update to existing rule | critical |
| [DLL Call by Ordinal Via Rundll32.EXE](pr-6279/rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_by_ordinal.kql) | update to existing rule | medium |
| [Tunneling Tool Execution](pr-6279/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_exfil_and_tunneling_tool_execution.kql) | update to existing rule | medium |
| [File or Folder Permissions Modifications](pr-6279/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_file_permission_modifications.kql) | update to existing rule | medium |
| [WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript](pr-6279/rules-threat-hunting/windows/process_creation/proc_creation_win_wscript_cscript_script_exec.kql) | update to existing rule | medium |
| [Cab File Extraction Via Wusa.EXE](pr-6279/rules-threat-hunting/windows/process_creation/proc_creation_win_wusa_cab_files_extraction.kql) | update to existing rule | medium |
| [Creation Exe for Service with Unquoted Path](pr-6279/rules/windows/file/file_event/file_event_win_creation_unquoted_service_path.kql) | update to existing rule | high |
| [DLL Search Order Hijackig Via Additional Space in Path](pr-6279/rules/windows/file/file_event/file_event_win_dll_sideloading_space_path.kql) | update to existing rule | high |
| [HackTool - Dumpert Process Dumper Default File](pr-6279/rules/windows/file/file_event/file_event_win_hktl_dumpert.kql) | update to existing rule | critical |
| [HackTool - Mimikatz Kirbi File Creation](pr-6279/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.kql) | update to existing rule | critical |
| [LSASS Process Memory Dump Files](pr-6279/rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.kql) | update to existing rule | high |
| [Potential Startup Shortcut Persistence Via PowerShell.EXE](pr-6279/rules/windows/file/file_event/file_event_win_powershell_startup_shortcuts.kql) | update to existing rule | high |
| [Startup Folder File Write](pr-6279/rules/windows/file/file_event/file_event_win_startup_folder_file_write.kql) | update to existing rule | medium |
| [Suspicious Desktopimgdownldr Target File](pr-6279/rules/windows/file/file_event/file_event_win_susp_desktopimgdownldr_file.kql) | update to existing rule | high |
| [Suspicious Startup Folder Persistence](pr-6279/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.kql) | update to existing rule | high |
| [Hijack Legit RDP Session to Move Laterally](pr-6279/rules/windows/file/file_event/file_event_win_tsclient_filewrite_startup.kql) | update to existing rule | high |
| [UAC Bypass Using .NET Code Profiler on MMC](pr-6279/rules/windows/file/file_event/file_event_win_uac_bypass_dotnet_profiler.kql) | update to existing rule | high |
| [UAC Bypass Using IEInstal - File](pr-6279/rules/windows/file/file_event/file_event_win_uac_bypass_ieinstal.kql) | update to existing rule | high |
| [UAC Bypass Using Windows Media Player - File](pr-6279/rules/windows/file/file_event/file_event_win_uac_bypass_wmp.kql) | update to existing rule | high |
| [PowerShell Core DLL Loaded By Non PowerShell Process](pr-6279/rules/windows/image_load/image_load_dll_system_management_automation_susp_load.kql) | update to existing rule | medium |
| [Potential DLL Sideloading Via comctl32.dll](pr-6279/rules/windows/image_load/image_load_side_load_comctl32.kql) | update to existing rule | high |
| [Potential System DLL Sideloading From Non System Locations](pr-6279/rules/windows/image_load/image_load_side_load_from_non_system_location.kql) | update to existing rule | high |
| [Fax Service DLL Search Order Hijack](pr-6279/rules/windows/image_load/image_load_side_load_ualapi.kql) | update to existing rule | high |
| [Potential WWlib.DLL Sideloading](pr-6279/rules/windows/image_load/image_load_side_load_wwlib.kql) | update to existing rule | medium |
| [DLL Load By System Process From Suspicious Locations](pr-6279/rules/windows/image_load/image_load_susp_dll_load_system_process.kql) | update to existing rule | medium |
| [Trusted Path Bypass via Windows Directory Spoofing](pr-6279/rules/windows/image_load/image_load_win_trusted_path_bypass.kql) | update to existing rule | high |
| [Network Connection Initiated Via Notepad.EXE](pr-6279/rules/windows/network_connection/net_connection_win_notepad.kql) | update to existing rule | high |
| [Network Connection Initiated By Regsvr32.EXE](pr-6279/rules/windows/network_connection/net_connection_win_regsvr32_network_activity.kql) | update to existing rule | medium |
| [Rundll32 Internet Connection](pr-6279/rules/windows/network_connection/net_connection_win_rundll32_net_connections.kql) | update to existing rule | medium |
| [Hiding Files with Attrib.exe](pr-6279/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.kql) | update to existing rule | medium |
| [Boot Configuration Tampering Via Bcdedit.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.kql) | update to existing rule | high |
| [Monitoring For Persistence Via BITS](pr-6279/rules/windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.kql) | update to existing rule | medium |
| [Unusual Parent Process For Cmd.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_cmd_unusual_parent.kql) | update to existing rule | medium |
| [Suspicious Desktopimgdownldr Command](pr-6279/rules/windows/process_creation/proc_creation_win_desktopimgdownldr_susp_execution.kql) | update to existing rule | high |
| [Potentially Suspicious Event Viewer Child Process](pr-6279/rules/windows/process_creation/proc_creation_win_eventvwr_susp_child_process.kql) | update to existing rule | high |
| [Explorer Process Tree Break](pr-6279/rules/windows/process_creation/proc_creation_win_explorer_break_process_tree.kql) | update to existing rule | medium |
| [Forfiles Command Execution](pr-6279/rules/windows/process_creation/proc_creation_win_forfiles_proxy_execution_.kql) | update to existing rule | medium |
| [Potential Arbitrary Command Execution Via FTP.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_ftp_arbitrary_command_execution.kql) | update to existing rule | medium |
| [HTML Help HH.EXE Suspicious Child Process](pr-6279/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.kql) | update to existing rule | high |
| [HackTool - Potential Impacket Lateral Movement Activity](pr-6279/rules/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.kql) | update to existing rule | high |
| [Potential Meterpreter/CobaltStrike Activity](pr-6279/rules/windows/process_creation/proc_creation_win_hktl_meterpreter_getsystem.kql) | update to existing rule | high |
| [Suspicious ZipExec Execution](pr-6279/rules/windows/process_creation/proc_creation_win_hktl_zipexec.kql) | update to existing rule | medium |
| [Microsoft IIS Service Account Password Dumped](pr-6279/rules/windows/process_creation/proc_creation_win_iis_appcmd_service_account_password_dumped.kql) | update to existing rule | high |
| [Gpscript Execution](pr-6279/rules/windows/process_creation/proc_creation_win_lolbin_gpscript.kql) | update to existing rule | medium |
| [Use of Pcalua For Execution](pr-6279/rules/windows/process_creation/proc_creation_win_lolbin_pcalua.kql) | update to existing rule | medium |
| [Code Execution via Pcwutl.dll](pr-6279/rules/windows/process_creation/proc_creation_win_lolbin_pcwutl.kql) | update to existing rule | medium |
| [Potential Credential Dumping Via LSASS Process Clone](pr-6279/rules/windows/process_creation/proc_creation_win_lsass_process_clone.kql) | update to existing rule | critical |
| [MMC20 Lateral Movement](pr-6279/rules/windows/process_creation/proc_creation_win_mmc_mmc20_lateral_movement.kql) | update to existing rule | high |
| [MMC Spawning Windows Shell](pr-6279/rules/windows/process_creation/proc_creation_win_mmc_susp_child_process.kql) | update to existing rule | high |
| [Wscript Shell Run In CommandLine](pr-6279/rules/windows/process_creation/proc_creation_win_mshta_inline_vbscript.kql) | update to existing rule | medium |
| [Potential LethalHTA Technique Execution](pr-6279/rules/windows/process_creation/proc_creation_win_mshta_lethalhta_technique.kql) | update to existing rule | high |
| [MSHTA Execution with Suspicious File Extensions](pr-6279/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.kql) | update to existing rule | high |
| [Suspicious Mshta.EXE Execution Patterns](pr-6279/rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.kql) | update to existing rule | high |
| [Suspicious Child Process Of SQL Server](pr-6279/rules/windows/process_creation/proc_creation_win_mssql_susp_child_process.kql) | update to existing rule | high |
| [Msxsl.EXE Execution](pr-6279/rules/windows/process_creation/proc_creation_win_msxsl_execution.kql) | update to existing rule | medium |
| [Windows Admin Share Mount Via Net.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_net_use_mount_admin_share.kql) | update to existing rule | medium |
| [New Firewall Rule Added Via Netsh.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_netsh_fw_add_rule.kql) | update to existing rule | medium |
| [RDP Connection Allowed Via Netsh.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_netsh_fw_allow_rdp.kql) | update to existing rule | high |
| [Potential Persistence Via Netsh Helper DLL](pr-6279/rules/windows/process_creation/proc_creation_win_netsh_helper_dll_persistence.kql) | update to existing rule | medium |
| [New Network Trace Capture Started Via Netsh.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_netsh_packet_capture.kql) | update to existing rule | medium |
| [New Port Forwarding Rule Added Via Netsh.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_netsh_port_forwarding.kql) | update to existing rule | medium |
| [RDP Port Forwarding Rule Added Via Netsh.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_netsh_port_forwarding_3389.kql) | update to existing rule | high |
| [Suspicious Binary In User Directory Spawned From Office Application](pr-6279/rules/windows/process_creation/proc_creation_win_office_spawn_exe_from_users_directory.kql) | update to existing rule | high |
| [Suspicious Microsoft Office Child Process](pr-6279/rules/windows/process_creation/proc_creation_win_office_susp_child_processes.kql) | update to existing rule | high |
| [Suspicious Plink Port Forwarding](pr-6279/rules/windows/process_creation/proc_creation_win_plink_port_forwarding.kql) | update to existing rule | high |
| [PowerShell Base64 Encoded IEX Cmdlet](pr-6279/rules/windows/process_creation/proc_creation_win_powershell_base64_iex.kql) | update to existing rule | high |
| [Gzip Archive Decode Via PowerShell](pr-6279/rules/windows/process_creation/proc_creation_win_powershell_decode_gzip.kql) | update to existing rule | medium |
| [Suspicious FromBase64String Usage On Gzip Archive - Process Creation](pr-6279/rules/windows/process_creation/proc_creation_win_powershell_frombase64string_archive.kql) | update to existing rule | medium |
| [Suspicious PowerShell Parent Process](pr-6279/rules/windows/process_creation/proc_creation_win_powershell_susp_parent_process.kql) | update to existing rule | high |
| [PUA - Netcat Suspicious Execution](pr-6279/rules/windows/process_creation/proc_creation_win_pua_netcat.kql) | update to existing rule | high |
| [Process Memory Dump via RdrLeakDiag.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.kql) | update to existing rule | high |
| [Direct Autorun Keys Modification](pr-6279/rules/windows/process_creation/proc_creation_win_reg_direct_asep_registry_keys_modification.kql) | update to existing rule | medium |
| [Potential Configuration And Service Reconnaissance Via Reg.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_reg_query_registry.kql) | update to existing rule | medium |
| [Potential Regsvr32 Commandline Flag Anomaly](pr-6279/rules/windows/process_creation/proc_creation_win_regsvr32_flags_anomaly.kql) | update to existing rule | medium |
| [Potentially Suspicious Regsvr32 HTTP/FTP Pattern](pr-6279/rules/windows/process_creation/proc_creation_win_regsvr32_network_pattern.kql) | update to existing rule | medium |
| [Potentially Suspicious Child Process Of Regsvr32](pr-6279/rules/windows/process_creation/proc_creation_win_regsvr32_susp_child_process.kql) | update to existing rule | high |
| [Regsvr32 Execution From Highly Suspicious Location](pr-6279/rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_2.kql) | update to existing rule | high |
| [Scripting/CommandLine Process Spawned Regsvr32](pr-6279/rules/windows/process_creation/proc_creation_win_regsvr32_susp_parent.kql) | update to existing rule | medium |
| [Renamed Office Binary Execution](pr-6279/rules/windows/process_creation/proc_creation_win_renamed_office_processes.kql) | update to existing rule | high |
| [Rundll32 Execution Without CommandLine Parameters](pr-6279/rules/windows/process_creation/proc_creation_win_rundll32_no_params.kql) | update to existing rule | high |
| [Rundll32 Spawned Via Explorer.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_rundll32_parent_explorer.kql) | update to existing rule | medium |
| [Suspicious Rundll32 Execution With Image Extension](pr-6279/rules/windows/process_creation/proc_creation_win_rundll32_susp_execution_with_image_extension.kql) | update to existing rule | high |
| [Rundll32 Execution Without Parameters](pr-6279/rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.kql) | update to existing rule | high |
| [Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_schtasks_env_folder.kql) | update to existing rule | medium |
| [Suspicious Scheduled Task Creation via Masqueraded XML File](pr-6279/rules/windows/process_creation/proc_creation_win_schtasks_schedule_via_masqueraded_xml_file.kql) | update to existing rule | medium |
| [Bad Opsec Defaults Sacrificial Processes With Improper Arguments](pr-6279/rules/windows/process_creation/proc_creation_win_susp_bad_opsec_sacrificial_processes.kql) | update to existing rule | high |
| [Suspicious Copy From or To System Directory](pr-6279/rules/windows/process_creation/proc_creation_win_susp_copy_system_dir.kql) | update to existing rule | medium |
| [Always Install Elevated MSI Spawned Cmd And Powershell](pr-6279/rules/windows/process_creation/proc_creation_win_susp_elavated_msi_spawned_shell.kql) | update to existing rule | medium |
| [Potentially Suspicious Execution From Parent Process In Public Folder](pr-6279/rules/windows/process_creation/proc_creation_win_susp_execution_from_public_folder_as_parent.kql) | update to existing rule | high |
| [Suspicious File Characteristics Due to Missing Fields](pr-6279/rules/windows/process_creation/proc_creation_win_susp_file_characteristics.kql) | update to existing rule | medium |
| [Use NTFS Short Name in Command Line](pr-6279/rules/windows/process_creation/proc_creation_win_susp_ntfs_short_name_use_cli.kql) | update to existing rule | medium |
| [Suspicious Process Parents](pr-6279/rules/windows/process_creation/proc_creation_win_susp_parents.kql) | update to existing rule | high |
| [Privilege Escalation via Named Pipe Impersonation](pr-6279/rules/windows/process_creation/proc_creation_win_susp_priv_escalation_via_named_pipe.kql) | update to existing rule | high |
| [Potential Remote Desktop Tunneling](pr-6279/rules/windows/process_creation/proc_creation_win_susp_remote_desktop_tunneling.kql) | update to existing rule | medium |
| [Shadow Copies Deletion Using Operating Systems Utilities](pr-6279/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.kql) | update to existing rule | high |
| [Suspicious SYSTEM User Process Creation](pr-6279/rules/windows/process_creation/proc_creation_win_susp_system_user_anomaly.kql) | update to existing rule | high |
| [Suspicious Userinit Child Process](pr-6279/rules/windows/process_creation/proc_creation_win_susp_userinit_child.kql) | update to existing rule | medium |
| [Suspect Svchost Activity](pr-6279/rules/windows/process_creation/proc_creation_win_svchost_execution_with_no_cli_flags.kql) | update to existing rule | high |
| [Uncommon Svchost Parent Process](pr-6279/rules/windows/process_creation/proc_creation_win_svchost_uncommon_parent_process.kql) | update to existing rule | medium |
| [PsExec Service Execution](pr-6279/rules/windows/process_creation/proc_creation_win_sysinternals_psexesvc.kql) | update to existing rule | medium |
| [Sysmon Configuration Update](pr-6279/rules/windows/process_creation/proc_creation_win_sysinternals_sysmon_config_update.kql) | update to existing rule | medium |
| [UAC Bypass Using ChangePK and SLUI](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_changepk_slui.kql) | update to existing rule | high |
| [UAC Bypass Using Disk Cleanup](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.kql) | update to existing rule | high |
| [Bypass UAC via CMSTP](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp.kql) | update to existing rule | high |
| [CMSTP UAC Bypass via COM Object Access](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp_com_object_access.kql) | update to existing rule | high |
| [UAC Bypass Using Consent and Comctl32 - Process](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_consent_comctl32.kql) | update to existing rule | high |
| [Bypass UAC via Fodhelper.exe](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_fodhelper.kql) | update to existing rule | high |
| [UAC Bypass via Windows Firewall Snap-In Hijack](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_hijacking_firwall_snap_in.kql) | update to existing rule | medium |
| [UAC Bypass via ICMLuaUtil](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_icmluautil.kql) | update to existing rule | high |
| [UAC Bypass Using IEInstal - Process](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_ieinstal.kql) | update to existing rule | high |
| [UAC Bypass Using NTFS Reparse Point - Process](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_ntfs_reparse_point.kql) | update to existing rule | high |
| [UAC Bypass Using PkgMgr and DISM](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_pkgmgr_dism.kql) | update to existing rule | high |
| [Potential UAC Bypass Via Sdclt.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_sdclt.kql) | update to existing rule | medium |
| [TrustedPath UAC Bypass Pattern](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_trustedpath.kql) | update to existing rule | critical |
| [Bypass UAC via WSReset.exe](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.kql) | update to existing rule | high |
| [UAC Bypass WSReset](pr-6279/rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset_integrity_level.kql) | update to existing rule | high |
| [Uncommon Userinit Child Process](pr-6279/rules/windows/process_creation/proc_creation_win_userinit_uncommon_child_processes.kql) | update to existing rule | high |
| [Proxy Execution via Vshadow](pr-6279/rules/windows/process_creation/proc_creation_win_vshadow_exec.kql) | update to existing rule | medium |
| [Webshell Hacking Activity Patterns](pr-6279/rules/windows/process_creation/proc_creation_win_webshell_hacking.kql) | update to existing rule | high |
| [Webshell Detection With Command Line Keywords](pr-6279/rules/windows/process_creation/proc_creation_win_webshell_recon_commands_and_processes.kql) | update to existing rule | high |
| [Suspicious Process By Web Server Process](pr-6279/rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.kql) | update to existing rule | high |
| [Suspicious Child Process Of Wermgr.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_wermgr_susp_child_process.kql) | update to existing rule | high |
| [Enumerate All Information With Whoami.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_whoami_all_execution.kql) | update to existing rule | medium |
| [Whoami.EXE Execution From Privileged Process](pr-6279/rules/windows/process_creation/proc_creation_win_whoami_execution_from_high_priv_process.kql) | update to existing rule | high |
| [Group Membership Reconnaissance Via Whoami.EXE](pr-6279/rules/windows/process_creation/proc_creation_win_whoami_groups_discovery.kql) | update to existing rule | medium |
| [Whoami.EXE Execution With Output Option](pr-6279/rules/windows/process_creation/proc_creation_win_whoami_output.kql) | update to existing rule | medium |
| [Whoami.EXE Execution Anomaly](pr-6279/rules/windows/process_creation/proc_creation_win_whoami_parent_anomaly.kql) | update to existing rule | medium |
| [Remote PowerShell Session Host Process (WinRM)](pr-6279/rules/windows/process_creation/proc_creation_win_winrm_remote_powershell_session_process.kql) | update to existing rule | medium |
| [WMI Persistence - Script Event Consumer](pr-6279/rules/windows/process_creation/proc_creation_win_wmi_persistence_script_event_consumer.kql) | update to existing rule | medium |
| [Suspicious WmiPrvSE Child Process](pr-6279/rules/windows/process_creation/proc_creation_win_wmiprvse_susp_child_processes.kql) | update to existing rule | high |
| [Potential Dropper Script Execution Via WScript/CScript/MSHTA](pr-6279/rules/windows/process_creation/proc_creation_win_wscript_cscript_mshta_dropper.kql) | update to existing rule | medium |
| [Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths](pr-6279/rules/windows/process_creation/proc_creation_win_wusa_cab_files_extraction_from_susp_paths.kql) | update to existing rule | high |
| [CMSTP App Paths Registry Key Modification](pr-6279/rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.kql) | update to existing rule | high |
| [New PortProxy Registry Entry Added](pr-6279/rules/windows/registry/registry_event/registry_event_portproxy_registry_key.kql) | update to existing rule | medium |
| [Shell Open Registry Keys Manipulation](pr-6279/rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.kql) | update to existing rule | high |
| [Sticky Key Like Backdoor Usage - Registry](pr-6279/rules/windows/registry/registry_event/registry_event_stickykey_like_backdoor.kql) | update to existing rule | critical |
| [DLL Load via LSASS](pr-6279/rules/windows/registry/registry_event/registry_event_susp_lsass_dll_load.kql) | update to existing rule | high |
| [Common Autorun Keys Modification](pr-6279/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_common.kql) | update to existing rule | medium |
| [CurrentVersion Autorun Keys Modification](pr-6279/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.kql) | update to existing rule | medium |
| [Potential CobaltStrike Service Installations - Registry](pr-6279/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.kql) | update to existing rule | high |
| [Registry Modification to Hidden File Extension](pr-6279/rules/windows/registry/registry_set/registry_set_hidden_extention.kql) | update to existing rule | medium |
| [Potential Persistence Via Netsh Helper DLL - Registry](pr-6279/rules/windows/registry/registry_set/registry_set_netsh_helper_dll_potential_persistence.kql) | update to existing rule | medium |
| [Trust Access Disable For VBApplications](pr-6279/rules/windows/registry/registry_set/registry_set_office_access_vbom_tamper.kql) | update to existing rule | high |
| [Potential Persistence Via Shim Database Modification](pr-6279/rules/windows/registry/registry_set/registry_set_persistence_shim_database.kql) | update to existing rule | medium |
| [PowerShell as a Service in Registry](pr-6279/rules/windows/registry/registry_set/registry_set_powershell_as_service.kql) | update to existing rule | high |
| [Suspicious PowerShell In Registry Run Keys](pr-6279/rules/windows/registry/registry_set/registry_set_powershell_in_run_keys.kql) | update to existing rule | medium |
| [ServiceDll Hijack](pr-6279/rules/windows/registry/registry_set/registry_set_servicedll_hijack.kql) | update to existing rule | medium |
| [RDP Sensitive Settings Changed](pr-6279/rules/windows/registry/registry_set/registry_set_terminal_server_tampering.kql) | update to existing rule | high |
| [UAC Disabled](pr-6279/rules/windows/registry/registry_set/registry_set_uac_disable.kql) | update to existing rule | medium |

## [#6274](https://github.com/SigmaHQ/sigma/pull/6274) Add 3 rules from a PyArmor-obfuscated PyInstaller loader detonation

| Rule | Change | Level |
|---|---|---|
| [Potential PyArmor Obfuscated PyInstaller Payload Extraction](pr-6274/rules/windows/file/file_event/file_event_win_pyarmor_runtime_in_pyinstaller_extraction.kql) | new rule | medium |
| [Suspicious Double Extension Executable Launched From User Writable Path](pr-6274/rules/windows/process_creation/proc_creation_win_double_extension_exec_user_writable.kql) | new rule | high |
| [Suspicious Microsoft Defender Exclusion Added Via WMIC](pr-6274/rules/windows/process_creation/proc_creation_win_wmic_defender_exclusion_added.kql) | new rule | high |

## [#6273](https://github.com/SigmaHQ/sigma/pull/6273) Add AmnesiaStealer macOS Detection Rules

| Rule | Change | Level |
|---|---|---|
| [AmnesiaStealer File Artifacts](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/file_event_macos_malware_amnesiastealer_artifacts.kql) | new rule | high |
| [AmnesiaStealer Headless Browser Remote Debugging Hijack](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/proc_creation_macos_malware_amnesiastealer_browser_debug_hijack.kql) | new rule | high |
| [AmnesiaStealer ClickFix Loader Execution](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/proc_creation_macos_malware_amnesiastealer_clickfix_loader.kql) | new rule | critical |
| [AmnesiaStealer Login Keychain Unlock Via Phished Password](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/proc_creation_macos_malware_amnesiastealer_keychain_unlock.kql) | new rule | high |
| [AmnesiaStealer Payload Staging And Gatekeeper Bypass](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/proc_creation_macos_malware_amnesiastealer_payload_staging.kql) | new rule | high |
| [AmnesiaStealer Privileged Collection Via Piped Password](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/proc_creation_macos_malware_amnesiastealer_sudo_password_abuse.kql) | new rule | high |
| [AmnesiaStealer TCC Bypass Via APFS Snapshot Mount](pr-6273/rules-emerging-threats/2026/Malware/AmnesiaStealer/proc_creation_macos_malware_amnesiastealer_tcc_snapshot_bypass.kql) | new rule | high |

## [#6264](https://github.com/SigmaHQ/sigma/pull/6264) New Rule: Potential Indirect Command Execution Via XBootMgr.EXE

| Rule | Change | Level |
|---|---|---|
| [Potential Indirect Command Execution Via XBootMgr.EXE](pr-6264/rules/windows/process_creation/proc_creation_win_xbootmgr_indirect_command_execution.kql) | new rule | medium |

## [#6262](https://github.com/SigmaHQ/sigma/pull/6262) new: add coverage for schtasks creation via Schedule.Service ComObject

| Rule | Change | Level |
|---|---|---|
| [Powershell Create Scheduled Task via CommandLine](pr-6262/rules/windows/process_creation/proc_creation_win_powershell_create_schtasks.kql) | new rule | medium |

## [#6258](https://github.com/SigmaHQ/sigma/pull/6258) New rule: Potential Virtualization/Sandbox Evasion Via WMI Or Registry Recon

| Rule | Change | Level |
|---|---|---|
| [Potential Virtualization/Sandbox Evasion Via WMI Or Registry Recon](pr-6258/rules/windows/process_creation/proc_creation_win_virt_sandbox_evasion_wmi_registry_recon.kql) | new rule | medium |

## [#6255](https://github.com/SigmaHQ/sigma/pull/6255) new: BTR Reforged Exploit

| Rule | Change | Level |
|---|---|---|
| [BTR Reforged Kernel Driver Service Changelist ADS Registration](pr-6255/rules-emerging-threats/2026/Exploits/BTR_Reforged/registry_set_win_btr_service_changelist_args.kql) | new rule | high |
| [Potential NtLoadDriver Syscall Abuse to Load Suspicious Kernel Driver Service](pr-6255/rules/windows/registry/registry_set/registry_set_ntloaddriver_service_type_kernel_driver_by_non_scm.kql) | new rule | medium |

## [#6252](https://github.com/SigmaHQ/sigma/pull/6252) new: Applaunch ClickOnce Activation

| Rule | Change | Level |
|---|---|---|
| [Applaunch ClickOnce Activation](pr-6252/rules/windows/process_creation/proc_creation_win_lolbin_applaunch.kql) | new rule | medium |

## [#6242](https://github.com/SigmaHQ/sigma/pull/6242) update: linux anti forensics rules

| Rule | Change | Level |
|---|---|---|
| [Linux Kernel Ring Buffer Cleared via Dmesg](pr-6242/rules/linux/process_creation/proc_creation_lnx_dmesg_clear_ring_buffer.kql) | new rule | medium |
| [File Deletion via Find and Shred](pr-6242/rules/linux/process_creation/proc_creation_lnx_find_exec_shred.kql) | new rule | high |
| [Shred with Zero-Fill Flag Used to Conceal Deletion](pr-6242/rules/linux/process_creation/proc_creation_lnx_shred_zero_fill.kql) | new rule | medium |
| [Shell Command History Tampering](pr-6242/rules/linux/process_creation/proc_creation_lnx_susp_history_delete.kql) | update to existing rule | high |

## [#6240](https://github.com/SigmaHQ/sigma/pull/6240) Fix renamed PowerShell detection in decryption pattern rule

| Rule | Change | Level |
|---|---|---|
| [PowerShell Execution With Potential Decryption Capabilities](pr-6240/rules/windows/process_creation/proc_creation_win_powershell_decrypt_pattern.kql) | update to existing rule | high |

## [#6236](https://github.com/SigmaHQ/sigma/pull/6236) new: closes #4542 - add rules for IFEO Debugger tampering, disabling usb storage and windowsupdate

| Rule | Change | Level |
|---|---|---|
| [IFEO Debugger Entry Attempted via Command Line](pr-6236/rules/windows/process_creation/proc_creation_win_ifeo_debugger_susp_value.kql) | new rule | medium |
| [USB Storage Service Disabled Via Registry](pr-6236/rules/windows/registry/registry_set/registry_set_disable_usb_storage.kql) | new rule | medium |
| [Windows Update Disabled Via Registry](pr-6236/rules/windows/registry/registry_set/registry_set_disable_windows_update.kql) | new rule | medium |
| [Process Execution Hijacking Via IFEO Debugger Entry](pr-6236/rules/windows/registry/registry_set/registry_set_ifeo_debugger_admin_tools_tamper.kql) | new rule | high |
| [Potential Third-Party Antivirus Protection Disabled Via Registry](pr-6236/rules/windows/registry/registry_set/registry_set_third_party_av_tamper.kql) | new rule | high |

## [#6234](https://github.com/SigmaHQ/sigma/pull/6234) Add macOS rule for sensitive data archived via ditto

| Rule | Change | Level |
|---|---|---|
| [Sensitive Data Archived Via Ditto - MacOS](pr-6234/rules/macos/process_creation/proc_creation_macos_sensitive_data_archived_via_ditto.kql) | new rule | medium |

## [#6233](https://github.com/SigmaHQ/sigma/pull/6233) Add macOS rule for browser credential database query via a database CLI utility

| Rule | Change | Level |
|---|---|---|
| [Browser Credential Database Query Via Database CLI Utility - MacOS](pr-6233/rules/macos/process_creation/proc_creation_macos_browser_credential_db_query_via_db_cli.kql) | new rule | medium |

## [#6230](https://github.com/SigmaHQ/sigma/pull/6230) new: silent-call rules

| Rule | Change | Level |
|---|---|---|
| [Sudo GDB Attach to PID 1](pr-6230/rules/linux/process_creation/proc_creation_lnx_sudo_gdb_attach_pid1.kql) | new rule | high |

## [#6229](https://github.com/SigmaHQ/sigma/pull/6229) new: SSH Authorized Keys Made Immutable

| Rule | Change | Level |
|---|---|---|
| [SSH Authorized Keys Made Immutable](pr-6229/rules/linux/process_creation/proc_creation_lnx_ssh_authorized_keys_made_immutable.kql) | new rule | medium |

## [#6219](https://github.com/SigmaHQ/sigma/pull/6219) Add New ChainDrop NPM Supply-Chain Attack Rules

| Rule | Change | Level |
|---|---|---|
| [ChainDrop Supply-Chain Attack File Creation Indicators - Linux](pr-6219/rules-emerging-threats/2026/Malware/ChainDrop/file_event_lnx_malware_chaindrop.kql) | new rule | high |
| [ChainDrop Supply-Chain Attack File Creation Indicators - Windows](pr-6219/rules-emerging-threats/2026/Malware/ChainDrop/file_event_win_malware_chaindrop.kql) | new rule | high |
| [ChainDrop Supply-Chain Attack Credential Access via Bun - Linux](pr-6219/rules-emerging-threats/2026/Malware/ChainDrop/proc_creation_lnx_malware_chaindrop_credential_access.kql) | new rule | high |
| [ChainDrop Supply-Chain Attack Credential Access via Bun - Windows](pr-6219/rules-emerging-threats/2026/Malware/ChainDrop/proc_creation_win_malware_chaindrop_credential_access.kql) | new rule | high |

## [#6218](https://github.com/SigmaHQ/sigma/pull/6218) Add Git configuration command execution rules

| Rule | Change | Level |
|---|---|---|
| [Shell Command in Git Configuration Value - Linux](pr-6218/rules/linux/process_creation/proc_creation_lnx_git_config_shell_value.kql) | new rule | high |
| [Git Pack or Proxy Program Override - Linux](pr-6218/rules/linux/process_creation/proc_creation_lnx_git_pack_proxy_program_override.kql) | new rule | medium |
| [Shell Command in Git Configuration Value - MacOS](pr-6218/rules/macos/process_creation/proc_creation_macos_git_config_shell_value.kql) | new rule | high |
| [Git Pack or Proxy Program Override - MacOS](pr-6218/rules/macos/process_creation/proc_creation_macos_git_pack_proxy_program_override.kql) | new rule | medium |
| [Shell Command in Git Configuration Value - Windows](pr-6218/rules/windows/process_creation/proc_creation_win_git_config_shell_value.kql) | new rule | high |
| [Git Pack or Proxy Program Override - Windows](pr-6218/rules/windows/process_creation/proc_creation_win_git_pack_proxy_program_override.kql) | new rule | medium |

## [#6217](https://github.com/SigmaHQ/sigma/pull/6217) new: Command Execution via Git Ext Transport

| Rule | Change | Level |
|---|---|---|
| [Command Execution via Git Ext Transport - Linux](pr-6217/rules/linux/process_creation/proc_creation_lnx_git_ext_transport_execution.kql) | new rule | high |
| [Command Execution via Git Ext Transport - MacOS](pr-6217/rules/macos/process_creation/proc_creation_macos_git_ext_transport_execution.kql) | new rule | high |
| [Command Execution via Git Ext Transport - Windows](pr-6217/rules/windows/process_creation/proc_creation_win_git_ext_transport_execution.kql) | new rule | high |

## [#6212](https://github.com/SigmaHQ/sigma/pull/6212) new: MFA Bypass via registry tampering and PowerShell requirement tam

| Rule | Change | Level |
|---|---|---|
| [MFA Bypass Via Windows Hello PIN Or Credential Provider Registry Tampering](pr-6212/rules/windows/registry/registry_set/registry_set_mfa_credential_provider_tampering.kql) | new rule | medium |

## [#6209](https://github.com/SigmaHQ/sigma/pull/6209) macOS: cover `launchctl bootstrap`, add AMOS LaunchDaemon install and wallet replacement rules

| Rule | Change | Level |
|---|---|---|
| [Atomic MacOS Stealer - Persistence Indicators](pr-6209/rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer/file_event_macos_malware_amos_persistence.kql) | update to existing rule | high |
| [Atomic MacOS Stealer - LaunchDaemon Installed With Piped Password](pr-6209/rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer/proc_creation_macos_malware_amos_launchdaemon_install.kql) | new rule | high |
| [Atomic MacOS Stealer - Cryptocurrency Wallet Application Replaced](pr-6209/rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer/proc_creation_macos_malware_amos_wallet_app_replacement.kql) | new rule | high |
| [Launch Agent/Daemon Execution Via Launchctl](pr-6209/rules/macos/process_creation/proc_creation_macos_launchctl_execution.kql) | update to existing rule | medium |

## [#6205](https://github.com/SigmaHQ/sigma/pull/6205) macOS: cover `xattr -c` in the Gatekeeper bypass rule, add ClickFix stage-3 dropper

| Rule | Change | Level |
|---|---|---|
| [macOS ClickFix Stage-3 Dropper Sequence](pr-6205/rules-emerging-threats/2026/Malware/ClickFix-macOS/proc_creation_macos_malware_clickfix_stage3_dropper.kql) | new rule | high |

## [#6201](https://github.com/SigmaHQ/sigma/pull/6201) Add rule: Sudo GTFOBins Shell Escape Privilege Escalation - Linux

| Rule | Change | Level |
|---|---|---|
| [Potential Privilege Escalation Via Sudo GTFOBins Shell Escape - Linux](pr-6201/rules/linux/process_creation/proc_creation_lnx_priv_esc_sudo_gtfobins_parent.kql) | new rule | high |

## [#6200](https://github.com/SigmaHQ/sigma/pull/6200) Add ClickLock Stealer macOS Detection Rules

| Rule | Change | Level |
|---|---|---|
| [ClickLock Stealer File Artifacts](pr-6200/rules-emerging-threats/2026/Malware/ClickLock-Stealer/file_event_macos_malware_clicklock_artifacts.kql) | new rule | high |
| [ClickLock Stealer Chrome Safe Storage Key Access](pr-6200/rules-emerging-threats/2026/Malware/ClickLock-Stealer/proc_creation_macos_malware_clicklock_keychain_access.kql) | new rule | high |

## [#6199](https://github.com/SigmaHQ/sigma/pull/6199) Add rule: HackTool - SharpSCCM Execution

| Rule | Change | Level |
|---|---|---|
| [HackTool - SharpSCCM Execution](pr-6199/rules/windows/process_creation/proc_creation_win_hktl_sharpsccm.kql) | new rule | high |

## [#6195](https://github.com/SigmaHQ/sigma/pull/6195) Add rule: HackTool - Kerbrute Execution

| Rule | Change | Level |
|---|---|---|
| [HackTool - Kerbrute Execution](pr-6195/rules/windows/process_creation/proc_creation_win_hktl_kerbrute.kql) | new rule | high |

## [#6187](https://github.com/SigmaHQ/sigma/pull/6187) new: Suspicious Bpftool State Modification

| Rule | Change | Level |
|---|---|---|
| [Suspicious Bpftool State Modification](pr-6187/rules/linux/process_creation/proc_creation_lnx_susp_bpftool.kql) | new rule | high |

## [#6186](https://github.com/SigmaHQ/sigma/pull/6186) new: SSH Authorized Keys Modification

| Rule | Change | Level |
|---|---|---|
| [SSH Authorized Keys Modification](pr-6186/rules/linux/file_event/file_event_lnx_ssh_authorized_keys_modification.kql) | new rule | medium |

## [#6184](https://github.com/SigmaHQ/sigma/pull/6184) Add CrashStealer macOS Detection Rules

| Rule | Change | Level |
|---|---|---|
| [CrashStealer File Artifacts](pr-6184/rules-emerging-threats/2026/Malware/CrashStealer/file_event_macos_malware_crashstealer_artifacts.kql) | new rule | high |
| [CrashStealer Dropper Activity](pr-6184/rules-emerging-threats/2026/Malware/CrashStealer/proc_creation_macos_malware_crashstealer_dropper.kql) | new rule | high |

## [#6183](https://github.com/SigmaHQ/sigma/pull/6183) Add PamStealer macOS Detection Rules

| Rule | Change | Level |
|---|---|---|
| [PamStealer File Artifacts](pr-6183/rules-emerging-threats/2026/Malware/PamStealer/file_event_macos_malware_pamstealer_artifacts.kql) | new rule | high |
| [PamStealer Clipboard Collection](pr-6183/rules-emerging-threats/2026/Malware/PamStealer/proc_creation_macos_malware_pamstealer_clipboard_collection.kql) | new rule | high |
| [PamStealer Ad-Hoc Bundle Signing Via Script Editor](pr-6183/rules-emerging-threats/2026/Malware/PamStealer/proc_creation_macos_malware_pamstealer_scripteditor_codesign.kql) | new rule | high |

## [#6179](https://github.com/SigmaHQ/sigma/pull/6179) new: suspicious user agent detected in SharePoint request

| Rule | Change | Level |
|---|---|---|
| [Suspicious File Write to SharePoint Layouts Directory](pr-6179/rules/windows/file/file_event/file_event_win_susp_filewrite_in_sharepoint_layouts_dir.kql) | update to existing rule | high |
| [Suspicious Process By Web Server Process](pr-6179/rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.kql) | update to existing rule | high |

## [#6176](https://github.com/SigmaHQ/sigma/pull/6176) Add NTUSER.MAN Persistence and HiveSwarming Detection Rules

| Rule | Change | Level |
|---|---|---|
| [Potential Mandatory Profile Persistence Via NTUSER.MAN Creation](pr-6176/rules/windows/file/file_event/file_event_win_ntuser_man_profile_creation.kql) | new rule | high |
| [HackTool - HiveSwarming Execution](pr-6176/rules/windows/process_creation/proc_creation_win_hktl_hiveswarming.kql) | new rule | high |

## [#6168](https://github.com/SigmaHQ/sigma/pull/6168) add sigma rules for Windows Sandbox

| Rule | Change | Level |
|---|---|---|
| [Headless SYSTEM-Context Command Execution Via Windows Sandbox CLI](pr-6168/rules/windows/process_creation/proc_creation_win_wsb_exec_system.kql) | new rule | medium |
| [Potential Fileless Execution Via Windows Sandbox CLI Inline LogonCommand](pr-6168/rules/windows/process_creation/proc_creation_win_wsb_inline_logoncommand.kql) | new rule | medium |
| [Arbitrary Command Execution Using Windows Sandbox CLI](pr-6168/rules/windows/process_creation/proc_creation_win_wsb_lolbin_execution.kql) | new rule | medium |
| [Runtime Read-Write Host-Folder Sharing Via Windows Sandbox CLI](pr-6168/rules/windows/process_creation/proc_creation_win_wsb_share_allow_write.kql) | new rule | medium |

## [#6166](https://github.com/SigmaHQ/sigma/pull/6166) feat: Add PUA - TruffleHog Execution macOS rule

| Rule | Change | Level |
|---|---|---|
| [PUA - TruffleHog Execution - macOS](pr-6166/rules/macos/process_creation/proc_creation_macos_pua_trufflehog.kql) | new rule | medium |

## [#6165](https://github.com/SigmaHQ/sigma/pull/6165) feat: Add Python One-Liners with Base64 Decoding macOS rule

| Rule | Change | Level |
|---|---|---|
| [Python One-Liners with Base64 Decoding - macOS](pr-6165/rules/macos/process_creation/proc_creation_macos_python_base64_encoded_execution.kql) | new rule | high |

## [#6163](https://github.com/SigmaHQ/sigma/pull/6163) New Agent Skills Installation Attempt Via Node - Linux

| Rule | Change | Level |
|---|---|---|
| [New Agent Skills Installation Attempt Via Node - Linux](pr-6163/rules/linux/process_creation/proc_creation_lnx_node_new_agent_skills_installed.kql) | new rule | medium |

## [#6162](https://github.com/SigmaHQ/sigma/pull/6162) New rule: Script Interpreter Spawning Credential Scanner - macOS

| Rule | Change | Level |
|---|---|---|
| [Script Interpreter Spawning Credential Scanner - macOS](pr-6162/rules/macos/process_creation/proc_creation_macos_susp_script_interpretor_spawn_credential_scanner.kql) | new rule | high |

## [#6157](https://github.com/SigmaHQ/sigma/pull/6157) Adding jscrambler npm supply chain attack detection case

| Rule | Change | Level |
|---|---|---|
| [Execution Of Binary Dropped By Compromised Jscrambler Npm Package](pr-6157/rules-emerging-threats/2026/Malware/Jscrambler-npm-package-compromised/proc_creation_win_jscrambler_npm_compromise_dropper_exec.kql) | new rule | high |
| [Binary Executed From A Temporal Directory By Node](pr-6157/rules-threat-hunting/windows/process_creation/proc_creation_win_temp_dir_binary_exec_by_node.kql) | new rule | medium |

## [#6152](https://github.com/SigmaHQ/sigma/pull/6152) new: detect potential proxy execution via setupugc

| Rule | Change | Level |
|---|---|---|
| [Suspicious Proxy Execution Via SetupUGC](pr-6152/rules/windows/process_creation/proc_creation_win_setupugc_proxy_execution.kql) | new rule | high |

## [#6143](https://github.com/SigmaHQ/sigma/pull/6143) new: WSL COM Proxy-Stub Loaded by Non-WSL Process

| Rule | Change | Level |
|---|---|---|
| [WSL COM Proxy-Stub Loaded by Non-WSL Process](pr-6143/rules/windows/image_load/image_load_wsl_com_proxystub_non_wsl.kql) | new rule | high |

## [#6134](https://github.com/SigmaHQ/sigma/pull/6134) Add .NET startup hook persistence detection

| Rule | Change | Level |
|---|---|---|
| [Potential .NET Startup Hook Persistence](pr-6134/rules/windows/registry/registry_set/registry_set_dotnet_startup_hooks.kql) | new rule | medium |

## [#6130](https://github.com/SigmaHQ/sigma/pull/6130) new: Node.js Package Manager Supply-Chain Execution Hunts (Windows/Linux/macOS)

| Rule | Change | Level |
|---|---|---|
| [Node.js Package Manager Spawning Download Or Reverse Shell - Linux](pr-6130/rules-threat-hunting/linux/process_creation/proc_creation_lnx_nodejs_pkg_manager_susp_child.kql) | new rule | medium |
| [Node.js Package Manager Spawning Download Or Reverse Shell - macOS](pr-6130/rules-threat-hunting/macos/process_creation/proc_creation_macos_nodejs_pkg_manager_susp_child.kql) | new rule | medium |
| [LOLBIN Or Encoded PowerShell Spawned By Node.js Package Manager](pr-6130/rules-threat-hunting/windows/process_creation/proc_creation_win_nodejs_pkg_manager_lolbin_execution.kql) | new rule | medium |

## [#6129](https://github.com/SigmaHQ/sigma/pull/6129) Add process creation rule for hidden local user account creation via net.exe

| Rule | Change | Level |
|---|---|---|
| [Hidden Local User Account Creation Attempt Via Net.EXE](pr-6129/rules/windows/process_creation/proc_creation_win_net_user_hidden_creation.kql) | new rule | high |
| [Creation of a Local Hidden User Account by Registry](pr-6129/rules/windows/registry/registry_event/registry_event_add_local_hidden_user.kql) | update to existing rule | high |

## [#6122](https://github.com/SigmaHQ/sigma/pull/6122) update: Regsvr32 detection rules tuning and expansion

| Rule | Change | Level |
|---|---|---|
| [Potential Regsvr32 Commandline Flag Anomaly](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_flags_anomaly.kql) | update to existing rule | medium |
| [Potentially Suspicious Regsvr32 Remote IPv4 Pattern](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_remote_ip_pattern.kql) | new rule | high |
| [Potentially Suspicious Regsvr32 Remote Pattern](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_remote_pattern.kql) | new rule | medium |
| [Suspicious Regsvr32 Execution From Remote Share](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_remote_share.kql) | update to existing rule | high |
| [Potentially Suspicious Child Process Of Regsvr32](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_susp_child_process.kql) | update to existing rule | high |
| [Regsvr32 DLL Execution With Suspicious File Extension](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_susp_extensions.kql) | update to existing rule | high |
| [Regsvr32 DLL Execution With Uncommon Extension](pr-6122/rules/windows/process_creation/proc_creation_win_regsvr32_uncommon_extension.kql) | update to existing rule | medium |
| [Rundll32 Execution With Uncommon DLL Extension](pr-6122/rules/windows/process_creation/proc_creation_win_rundll32_uncommon_dll_extension.kql) | update to existing rule | medium |

## [#6111](https://github.com/SigmaHQ/sigma/pull/6111) Add rule: potential NTLM authentication coercion tool execution

| Rule | Change | Level |
|---|---|---|
| [Potential NTLM Authentication Coercion Tool Execution](pr-6111/rules/windows/process_creation/proc_creation_win_hktl_ntlm_coercion_tools.kql) | new rule | high |

## [#6107](https://github.com/SigmaHQ/sigma/pull/6107) fix: net user rules coverage and deprecate redundant rule

| Rule | Change | Level |
|---|---|---|
| [Potential Binary Or Script Dropper Via PowerShell](pr-6107/rules/windows/file/file_event/file_event_win_powershell_drop_binary_or_script.kql) | update to existing rule | medium |
| [Suspicious Manipulation Of Default Accounts Via Net.EXE](pr-6107/rules/windows/process_creation/proc_creation_win_net_user_default_accounts_manipulation.kql) | update to existing rule | high |
| [User Account Configured With Never Expire Option Via Net.EXE](pr-6107/rules/windows/process_creation/proc_creation_win_net_user_never_expire.kql) | new rule | high |
| [Local And Domain Account Discovery Via Net.EXE](pr-6107/rules/windows/process_creation/proc_creation_win_net_user_recon.kql) | new rule | medium |
| [Reg Add Suspicious Paths](pr-6107/rules/windows/process_creation/proc_creation_win_reg_susp_paths.kql) | update to existing rule | high |

## [#6104](https://github.com/SigmaHQ/sigma/pull/6104) Add rule: indirect command execution via scp.exe

| Rule | Change | Level |
|---|---|---|
| [Indirect Command Execution Via Scp.EXE](pr-6104/rules/windows/process_creation/proc_creation_win_scp_proxy_command_execution.kql) | new rule | medium |

## [#6103](https://github.com/SigmaHQ/sigma/pull/6103) Add rule: arbitrary command execution via git config override

| Rule | Change | Level |
|---|---|---|
| [Potential Arbitrary Command Execution Via Git Config Override](pr-6103/rules/windows/process_creation/proc_creation_win_git_config_command_execution.kql) | new rule | medium |

## [#6099](https://github.com/SigmaHQ/sigma/pull/6099) Add detection for PnPUtil driver and device removal activity

| Rule | Change | Level |
|---|---|---|
| [Suspicious Driver or Device Removal via PnPUtil](pr-6099/rules/windows/process_creation/proc_creation_win_pnputil_driver_device_removal.kql) | new rule | medium |

## [#6095](https://github.com/SigmaHQ/sigma/pull/6095) Add cross-platform discovery/collection rules

| Rule | Change | Level |
|---|---|---|
| [Safe Mode Boot Configuration Via Bcdedit.EXE](pr-6095/rules/windows/process_creation/proc_creation_win_bcdedit_safeboot_config.kql) | new rule | high |
| [Data Collection From Removable Media Via PowerShell](pr-6095/rules/windows/process_creation/proc_creation_win_data_from_removable_media.kql) | new rule | medium |

## [#6094](https://github.com/SigmaHQ/sigma/pull/6094) Add Sysinternals tooling and driver/UAC detection rules

| Rule | Change | Level |
|---|---|---|
| [Potential DLL Sideloading Via AccCheckConsole.EXE](pr-6094/rules/windows/image_load/image_load_lolbin_acccheckconsole_dll.kql) | new rule | medium |
| [Volume Image Creation Via Disk2vhd](pr-6094/rules/windows/process_creation/proc_creation_win_disk2vhd_volume_image.kql) | new rule | medium |
| [Potential NTDS.DIT Dump Via Dsdbutil.EXE](pr-6094/rules/windows/process_creation/proc_creation_win_dsdbutil_ntds_dump.kql) | new rule | high |
| [Network Capture Via Nmcap.EXE](pr-6094/rules/windows/process_creation/proc_creation_win_nmcap_network_capture.kql) | new rule | medium |
| [Security Software Termination Via PsKill](pr-6094/rules/windows/process_creation/proc_creation_win_pskill_security_process_termination.kql) | new rule | high |
| [Timestomping Via Known Utilities](pr-6094/rules/windows/process_creation/proc_creation_win_timestomp_tools.kql) | new rule | high |
| [UAC Bypass Tool Spawning Shell - Odbcad32/Eudcedit](pr-6094/rules/windows/process_creation/proc_creation_win_uac_bypass_odbcad32_eudcedit.kql) | new rule | high |
| [WMI Test Tool Execution - Wbemtest.EXE](pr-6094/rules/windows/process_creation/proc_creation_win_wbemtest_execution.kql) | new rule | medium |
| [Kernel Driver Service Registered From Suspicious Path](pr-6094/rules/windows/registry/registry_set/registry_set_kernel_driver_service_suspicious_path.kql) | new rule | high |

## [#6092](https://github.com/SigmaHQ/sigma/pull/6092) Add ADS abuse and signed-binary LOLBIN detection rules

| Rule | Change | Level |
|---|---|---|
| [Esentutl Write To Alternate Data Stream](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_esentutl_ads.kql) | new rule | high |
| [Expand Write To Alternate Data Stream](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_expand_ads.kql) | new rule | high |
| [Forfiles Command Execution From Alternate Data Stream](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_forfiles_ads.kql) | new rule | high |
| [Makecab Compression Into Alternate Data Stream](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_makecab_ads.kql) | new rule | high |
| [Remote File Download Via Signed Microsoft LOLBin](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_ms_signed_remote_download.kql) | new rule | high |
| [Tar Archive Into Alternate Data Stream](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_tar_ads.kql) | new rule | high |
| [Application Whitelisting Bypass Via Microsoft.Workflow.Compiler.EXE](pr-6092/rules/windows/process_creation/proc_creation_win_lolbin_workflow_compiler.kql) | new rule | high |
| [Proxy Execution Via Mscopilot.EXE GPU-Launcher](pr-6092/rules/windows/process_creation/proc_creation_win_mscopilot_gpu_launcher_proxy_exec.kql) | new rule | high |
| [Application Whitelisting Bypass Via Syssetup.DLL](pr-6092/rules/windows/process_creation/proc_creation_win_rundll32_syssetup_installaction.kql) | new rule | high |
| [Alternate Data Stream Manipulation Via Streams.EXE](pr-6092/rules/windows/process_creation/proc_creation_win_streams_ads_manipulation.kql) | new rule | medium |
| [Potential AWL Bypass Via Vstest.Console.EXE](pr-6092/rules/windows/process_creation/proc_creation_win_vstest_console_awl_bypass.kql) | new rule | medium |

## [#6091](https://github.com/SigmaHQ/sigma/pull/6091) Enrich ATT&CK tags (T1654/T1652) and dedupe bcdedit safeboot logic

| Rule | Change | Level |
|---|---|---|
| [EventLog Query Requests By Builtin Utilities](pr-6091/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_event_log_query.kql) | update to existing rule | medium |
| [Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE](pr-6091/rules/windows/process_creation/proc_creation_win_bcdedit_susp_execution.kql) | update to existing rule | medium |
| [Potential Recon Activity Using DriverQuery.EXE](pr-6091/rules/windows/process_creation/proc_creation_win_driverquery_recon.kql) | update to existing rule | high |

## [#6089](https://github.com/SigmaHQ/sigma/pull/6089) rules/windows: add Dev Tunnel hosting or creation process_creation rule

| Rule | Change | Level |
|---|---|---|
| [Dev Tunnel Hosting Or Creation Execution](pr-6089/rules/windows/process_creation/proc_creation_win_devtunnel_host_execution.kql) | new rule | medium |

## [#6083](https://github.com/SigmaHQ/sigma/pull/6083) new: Dindoor Backdoor Malware rule

| Rule | Change | Level |
|---|---|---|
| [DinDoor Backdoor Deno Remote JavaScript Execution From PowerShell](pr-6083/rules-emerging-threats/2026/Malware/DinDoor-Backdoor/proc_creation_win_malware_dindoor_deno_remote_js.kql) | new rule | medium |

