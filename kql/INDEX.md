# Sigma rules in KQL (microsoft_xdr)

1910 rules converted from SigmaHQ commit [`52f81d60d5`](https://github.com/SigmaHQ/sigma/commit/52f81d60d5ea122e49a34b2289ea0c2a7bb0b113). Last run: 2026-11-05 14:43 UTC.

Rules are licensed under the Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License. Each file keeps the original author and Sigma ID.

> [!WARNING]
> These queries are machine-generated and have not been tested against real telemetry. Validation confirms they are valid KQL, not that they detect what the Sigma rule describes. Run them as hunts and tune them before using any as a detection.

## rules (1629)

| Rule | Level | ATT&CK | Table |
|---|---|---|---|
| [Linux Doas Conf File Creation](rules/linux/file_event/file_event_lnx_doas_conf_creation.kql) | medium | privilege-escalation, T1548 | DeviceFileEvents |
| [Persistence Via Sudoers Files](rules/linux/file_event/file_event_lnx_persistence_sudoers_files.kql) | medium | privilege-escalation, persistence, T1548.003 | DeviceFileEvents |
| [Triple Cross eBPF Rootkit Default LockFile](rules/linux/file_event/file_event_lnx_triple_cross_rootkit_lock_file.kql) | high | stealth | DeviceFileEvents |
| [Triple Cross eBPF Rootkit Default Persistence](rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.kql) | high | privilege-escalation, execution, persistence, T1053.003 | DeviceFileEvents |
| [Wget Creating Files in Tmp Directory](rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.kql) | medium | command-and-control, T1105 | DeviceFileEvents |
| [Linux Reverse Shell Indicator](rules/linux/network_connection/net_connection_lnx_back_connect_shell_dev.kql) | critical | execution, T1059.004 | DeviceNetworkEvents |
| [Linux Crypto Mining Pool Connections](rules/linux/network_connection/net_connection_lnx_crypto_mining_indicators.kql) | high | impact, T1496 | DeviceNetworkEvents |
| [Communication To LocaltoNet Tunneling Service Initiated - Linux](rules/linux/network_connection/net_connection_lnx_domain_localtonet_tunnel.kql) | high | command-and-control, T1572, T1090, T1102 | DeviceNetworkEvents |
| [Communication To Ngrok Tunneling Service - Linux](rules/linux/network_connection/net_connection_lnx_ngrok_tunnel.kql) | high | exfiltration, command-and-control, T1567, T1568.002, T1572, T1090, T1102, S0508 | DeviceNetworkEvents |
| [Shell Invocation via Apt - Linux](rules/linux/process_creation/proc_creation_lnx_apt_shell_execution.kql) | medium | discovery, T1083 | DeviceProcessEvents |
| [Suspicious Invocation of Shell via AWK - Linux](rules/linux/process_creation/proc_creation_lnx_awk_shell_spawn.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Linux Base64 Encoded Pipe to Shell](rules/linux/process_creation/proc_creation_lnx_base64_execution.kql) | medium | stealth, T1140 | DeviceProcessEvents |
| [Linux Base64 Encoded Shebang In CLI](rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.kql) | medium | stealth, T1140 | DeviceProcessEvents |
| [Enable BPF Kprobes Tracing](rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.kql) | medium | execution, stealth | DeviceProcessEvents |
| [BPFtrace Unsafe Option Usage](rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.kql) | medium | execution, T1059.004 | DeviceProcessEvents |
| [Capsh Shell Invocation - Linux](rules/linux/process_creation/proc_creation_lnx_capsh_shell_invocation.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Remove Immutable File Attribute](rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.kql) | medium | defense-impairment, T1222.002 | DeviceProcessEvents |
| [Chmod Targeting Sensitive Directories](rules/linux/process_creation/proc_creation_lnx_chmod_targeting_sensitive_directories.kql) | medium | defense-impairment, T1222.002 | DeviceProcessEvents |
| [Linux Logs Clearing Attempts](rules/linux/process_creation/proc_creation_lnx_clear_logs.kql) | medium | defense-impairment, T1685.006 | DeviceProcessEvents |
| [Syslog Clearing or Removal Via System Utilities](rules/linux/process_creation/proc_creation_lnx_clear_syslog.kql) | high | defense-impairment, T1685.006 | DeviceProcessEvents |
| [Copy Passwd Or Shadow From TMP Path](rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.kql) | high | credential-access, T1552.001 | DeviceProcessEvents |
| [Remove Scheduled Cron Task/Job](rules/linux/process_creation/proc_creation_lnx_crontab_removal.kql) | medium | stealth | DeviceProcessEvents |
| [Linux Crypto Mining Indicators](rules/linux/process_creation/proc_creation_lnx_crypto_mining.kql) | high | impact, T1496 | DeviceProcessEvents |
| [Potential Linux Process Code Injection Via DD Utility](rules/linux/process_creation/proc_creation_lnx_dd_process_injection.kql) | medium | privilege-escalation, stealth, T1055.009 | DeviceProcessEvents |
| [UFW Disable Attempt](rules/linux/process_creation/proc_creation_lnx_disable_ufw.kql) | medium | defense-impairment, T1686 | DeviceProcessEvents |
| [Shell Invocation via Env Command - Linux](rules/linux/process_creation/proc_creation_lnx_env_shell_invocation.kql) | high | execution, T1059.004 | DeviceProcessEvents |
| [ESXi Network Configuration Discovery Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_network_discovery.kql) | medium | discovery, execution, T1033, T1007, T1059.012 | DeviceProcessEvents |
| [ESXi Admin Permission Assigned To Account Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_permission_change_admin.kql) | high | persistence, execution, privilege-escalation, T1059.012, T1098 | DeviceProcessEvents |
| [ESXi Storage Information Discovery Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_storage_discovery.kql) | medium | discovery, execution, T1033, T1007, T1059.012 | DeviceProcessEvents |
| [ESXi Syslog Configuration Change Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_syslog_config_change.kql) | medium | execution, defense-impairment, T1685, T1690, T1059.012 | DeviceProcessEvents |
| [ESXi System Information Discovery Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_system_discovery.kql) | medium | discovery, execution, T1033, T1007, T1059.012 | DeviceProcessEvents |
| [ESXi Account Creation Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_user_account_creation.kql) | medium | persistence, execution, T1136, T1059.012 | DeviceProcessEvents |
| [ESXi VM List Discovery Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_vm_discovery.kql) | medium | discovery, execution, T1033, T1007, T1059.012 | DeviceProcessEvents |
| [ESXi VM Kill Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_vm_kill.kql) | medium | execution, impact, T1059.012, T1529 | DeviceProcessEvents |
| [ESXi VSAN Information Discovery Via ESXCLI](rules/linux/process_creation/proc_creation_lnx_esxcli_vsan_discovery.kql) | medium | discovery, execution, T1033, T1007, T1059.012 | DeviceProcessEvents |
| [Shell Execution via Find - Linux](rules/linux/process_creation/proc_creation_lnx_find_shell_execution.kql) | high | discovery, T1083 | DeviceProcessEvents |
| [Shell Execution via Flock - Linux](rules/linux/process_creation/proc_creation_lnx_flock_shell_execution.kql) | high | discovery, T1083 | DeviceProcessEvents |
| [Shell Execution GCC  - Linux](rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.kql) | high | discovery, T1083 | DeviceProcessEvents |
| [Shell Execution via Git - Linux](rules/linux/process_creation/proc_creation_lnx_git_shell_execution.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Group Has Been Deleted Via Groupdel](rules/linux/process_creation/proc_creation_lnx_groupdel.kql) | medium | impact, T1531 | DeviceProcessEvents |
| [Suspicious Package Installed - Linux](rules/linux/process_creation/proc_creation_lnx_install_suspicious_packages.kql) | medium | defense-impairment, T1553.004 | DeviceProcessEvents |
| [Flush Iptables Ufw Chain](rules/linux/process_creation/proc_creation_lnx_iptables_flush_ufw.kql) | medium | defense-impairment, T1686 | DeviceProcessEvents |
| [Potential GobRAT File Discovery Via Grep](rules/linux/process_creation/proc_creation_lnx_malware_gobrat_grep_payload_discovery.kql) | high | discovery, T1082 | DeviceProcessEvents |
| [Potentially Suspicious Named Pipe Created Via Mkfifo](rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation_susp_location.kql) | medium | execution | DeviceProcessEvents |
| [Mount Execution With Hidepid Parameter](rules/linux/process_creation/proc_creation_lnx_mount_hidepid.kql) | medium | credential-access, stealth, T1564 | DeviceProcessEvents |
| [Potential Netcat Reverse Shell Execution](rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Shell Execution via Nice - Linux](rules/linux/process_creation/proc_creation_lnx_nice_shell_execution.kql) | high | discovery, T1083 | DeviceProcessEvents |
| [Nohup Execution](rules/linux/process_creation/proc_creation_lnx_nohup.kql) | medium | execution, T1059.004 | DeviceProcessEvents |
| [Suspicious Nohup Execution](rules/linux/process_creation/proc_creation_lnx_nohup_susp_execution.kql) | high | execution | DeviceProcessEvents |
| [Potential Perl Reverse Shell Execution](rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.kql) | high | execution | DeviceProcessEvents |
| [Potential PHP Reverse Shell](rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.kql) | high | execution | DeviceProcessEvents |
| [Pnscan Binary Data Transmission Activity](rules/linux/process_creation/proc_creation_lnx_pnscan_binary_cli_pattern.kql) | medium | discovery, T1046 | DeviceProcessEvents |
| [Python Spawning Pretty TTY Via PTY Module](rules/linux/process_creation/proc_creation_lnx_python_pty_spawn.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Python Reverse Shell Execution Via PTY And Socket Modules](rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.kql) | high | execution | DeviceProcessEvents |
| [Inline Python Execution - Spawn Shell Via OS System Library](rules/linux/process_creation/proc_creation_lnx_python_shell_os_system.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Potential Ruby Reverse Shell](rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.kql) | medium | execution | DeviceProcessEvents |
| [Scheduled Cron Task/Job - Linux](rules/linux/process_creation/proc_creation_lnx_schedule_task_job_cron.kql) | medium | execution, persistence, privilege-escalation, T1053.003 | DeviceProcessEvents |
| [Disabling Security Tools](rules/linux/process_creation/proc_creation_lnx_security_tools_disabling.kql) | medium | defense-impairment, T1686 | DeviceProcessEvents |
| [Disable Or Stop Services](rules/linux/process_creation/proc_creation_lnx_services_stop_and_disable.kql) | medium | defense-impairment, T1685, impact, T1489 | DeviceProcessEvents |
| [Shell Invocation Via Ssh - Linux](rules/linux/process_creation/proc_creation_lnx_ssh_shell_execution.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Potential Linux Amazon SSM Agent Hijacking](rules/linux/process_creation/proc_creation_lnx_ssm_agent_abuse.kql) | medium | command-and-control, persistence, T1219.002 | DeviceProcessEvents |
| [Suspicious Curl File Upload - Linux](rules/linux/process_creation/proc_creation_lnx_susp_curl_fileupload.kql) | medium | exfiltration, command-and-control, T1567, T1105 | DeviceProcessEvents |
| [Suspicious Curl Change User Agents - Linux](rules/linux/process_creation/proc_creation_lnx_susp_curl_useragent.kql) | medium | command-and-control, T1071.001 | DeviceProcessEvents |
| [Potentially Suspicious Execution From Tmp Folder](rules/linux/process_creation/proc_creation_lnx_susp_execution_tmp_folder.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [Potential Discovery Activity Using Find - Linux](rules/linux/process_creation/proc_creation_lnx_susp_find_execution.kql) | medium | discovery, T1083 | DeviceProcessEvents |
| [Suspicious Git Clone - Linux](rules/linux/process_creation/proc_creation_lnx_susp_git_clone.kql) | medium | reconnaissance, T1593.003 | DeviceProcessEvents |
| [History File Deletion](rules/linux/process_creation/proc_creation_lnx_susp_history_delete.kql) | high | impact, T1565.001 | DeviceProcessEvents |
| [Print History File Contents](rules/linux/process_creation/proc_creation_lnx_susp_history_recon.kql) | medium | reconnaissance, T1592.004 | DeviceProcessEvents |
| [Linux HackTool Execution](rules/linux/process_creation/proc_creation_lnx_susp_hktl_execution.kql) | high | execution, resource-development, T1587 | DeviceProcessEvents |
| [Interactive Bash Suspicious Children](rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.kql) | medium | execution, stealth, T1059.004, T1036 | DeviceProcessEvents |
| [Suspicious Java Children Processes](rules/linux/process_creation/proc_creation_lnx_susp_java_children.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Linux Shell Pipe to Shell](rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.kql) | medium | stealth, T1140 | DeviceProcessEvents |
| [Access of Sudoers File Content](rules/linux/process_creation/proc_creation_lnx_susp_process_reading_sudoers.kql) | medium | reconnaissance, T1592.004 | DeviceProcessEvents |
| [Linux Recon Indicators](rules/linux/process_creation/proc_creation_lnx_susp_recon_indicators.kql) | high | reconnaissance, T1592.004, credential-access, T1552.001 | DeviceProcessEvents |
| [Potential Suspicious Change To Sensitive/Critical Files](rules/linux/process_creation/proc_creation_lnx_susp_sensitive_file_access.kql) | medium | impact, T1565.001 | DeviceProcessEvents |
| [Shell Execution Of Process Located In Tmp Directory](rules/linux/process_creation/proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder.kql) | high | execution | DeviceProcessEvents |
| [Execution Of Script Located In Potentially Suspicious Directory](rules/linux/process_creation/proc_creation_lnx_susp_shell_script_exec_from_susp_location.kql) | medium | execution | DeviceProcessEvents |
| [Touch Suspicious Service File](rules/linux/process_creation/proc_creation_lnx_touch_susp.kql) | medium | stealth, T1070.006 | DeviceProcessEvents |
| [Triple Cross eBPF Rootkit Execve Hijack](rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_execve_hijack.kql) | high | privilege-escalation, stealth | DeviceProcessEvents |
| [Triple Cross eBPF Rootkit Install Commands](rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_install.kql) | high | stealth, T1014 | DeviceProcessEvents |
| [User Has Been Deleted Via Userdel](rules/linux/process_creation/proc_creation_lnx_userdel.kql) | medium | impact, T1531 | DeviceProcessEvents |
| [User Added To Root/Sudoers Group Using Usermod](rules/linux/process_creation/proc_creation_lnx_usermod_susp_group.kql) | medium | privilege-escalation, persistence | DeviceProcessEvents |
| [Vim GTFOBin Abuse - Linux](rules/linux/process_creation/proc_creation_lnx_vim_shell_execution.kql) | high | execution, discovery, T1059, T1083 | DeviceProcessEvents |
| [Linux Webshell Indicators](rules/linux/process_creation/proc_creation_lnx_webshell_detection.kql) | high | persistence, T1505.003 | DeviceProcessEvents |
| [Download File To Potentially Suspicious Directory Via Wget](rules/linux/process_creation/proc_creation_lnx_wget_download_suspicious_directory.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Potential Xterm Reverse Shell](rules/linux/process_creation/proc_creation_lnx_xterm_reverse_shell.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [MacOS Emond Launch Daemon](rules/macos/file_event/file_event_macos_emond_launch_daemon.kql) | medium | persistence, privilege-escalation, T1546.014 | DeviceFileEvents |
| [MacOS Scripting Interpreter AppleScript](rules/macos/process_creation/proc_creation_macos_applescript.kql) | medium | execution, T1059.002 | DeviceProcessEvents |
| [Binary Padding - MacOS](rules/macos/process_creation/proc_creation_macos_binary_padding.kql) | high | stealth, T1027.001 | DeviceProcessEvents |
| [File Time Attribute Change](rules/macos/process_creation/proc_creation_macos_change_file_time_attr.kql) | medium | stealth, T1070.006 | DeviceProcessEvents |
| [Hidden Flag Set On File/Directory Via Chflags - MacOS](rules/macos/process_creation/proc_creation_macos_chflags_hidden_flag.kql) | medium | credential-access, command-and-control, stealth, T1218, T1564.004, T1552.001, T1105 | DeviceProcessEvents |
| [Indicator Removal on Host - Clear Mac System Logs](rules/macos/process_creation/proc_creation_macos_clear_system_logs.kql) | medium | defense-impairment, T1685.006 | DeviceProcessEvents |
| [Clipboard Access Via OSAScript](rules/macos/process_creation/proc_creation_macos_clipboard_access_via_osascript.kql) | medium | collection, execution, T1115, T1059.002 | DeviceProcessEvents |
| [Hidden User Creation](rules/macos/process_creation/proc_creation_macos_create_hidden_account.kql) | medium | stealth, T1564.002 | DeviceProcessEvents |
| [Credentials from Password Stores - Keychain](rules/macos/process_creation/proc_creation_macos_creds_from_keychain.kql) | medium | credential-access, T1555.001 | DeviceProcessEvents |
| [System Integrity Protection (SIP) Disabled](rules/macos/process_creation/proc_creation_macos_csrutil_disable.kql) | medium | discovery, T1518.001 | DeviceProcessEvents |
| [Disable Security Tools](rules/macos/process_creation/proc_creation_macos_disable_security_tools.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [User Added To Admin Group Via Dscl](rules/macos/process_creation/proc_creation_macos_dscl_add_user_to_admin_group.kql) | medium | persistence, initial-access, privilege-escalation, stealth, T1078.003 | DeviceProcessEvents |
| [User Added To Admin Group Via DseditGroup](rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.kql) | medium | persistence, initial-access, privilege-escalation, stealth, T1078.003 | DeviceProcessEvents |
| [Root Account Enable Via Dsenableroot](rules/macos/process_creation/proc_creation_macos_dsenableroot_enable_root_account.kql) | medium | privilege-escalation, stealth, T1078, T1078.001, T1078.003, initial-access, persistence | DeviceProcessEvents |
| [Credentials In Files](rules/macos/process_creation/proc_creation_macos_find_cred_in_files.kql) | high | credential-access, T1552.001 | DeviceProcessEvents |
| [Disk Image Creation Via Hdiutil - MacOS](rules/macos/process_creation/proc_creation_macos_hdiutil_create.kql) | medium | exfiltration | DeviceProcessEvents |
| [Disk Image Mounting Via Hdiutil - MacOS](rules/macos/process_creation/proc_creation_macos_hdiutil_mount.kql) | medium | initial-access, collection, T1566.001, T1560.001 | DeviceProcessEvents |
| [Suspicious Installer Package Child Process](rules/macos/process_creation/proc_creation_macos_installer_susp_child_process.kql) | medium | T1059, T1059.007, T1071, T1071.001, execution, command-and-control | DeviceProcessEvents |
| [System Information Discovery Using Ioreg](rules/macos/process_creation/proc_creation_macos_ioreg_discovery.kql) | medium | discovery, T1082 | DeviceProcessEvents |
| [JAMF MDM Potential Suspicious Child Process](rules/macos/process_creation/proc_creation_macos_jamf_susp_child.kql) | medium | execution | DeviceProcessEvents |
| [JXA In-memory Execution Via OSAScript](rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.kql) | high | T1059.002, T1059.007, execution | DeviceProcessEvents |
| [Launch Agent/Daemon Execution Via Launchctl](rules/macos/process_creation/proc_creation_macos_launchctl_execution.kql) | medium | privilege-escalation, execution, persistence, T1569.001, T1543.001, T1543.004 | DeviceProcessEvents |
| [File Download Via Nscurl - MacOS](rules/macos/process_creation/proc_creation_macos_nscurl_usage.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Microsoft Office Child Process - MacOS](rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.kql) | high | execution, persistence, T1059.002, T1137.002, T1204.002 | DeviceProcessEvents |
| [OSACompile Run-Only Execution](rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.kql) | high | T1059.002, execution | DeviceProcessEvents |
| [Payload Decoded and Decrypted via Built-in Utilities](rules/macos/process_creation/proc_creation_macos_payload_decoded_and_decrypted.kql) | medium | stealth, T1059, T1204, execution, T1140, S0482, S0402 | DeviceProcessEvents |
| [Potential Persistence Via PlistBuddy](rules/macos/process_creation/proc_creation_macos_persistence_via_plistbuddy.kql) | high | privilege-escalation, persistence, T1543.001, T1543.004 | DeviceProcessEvents |
| [Scheduled Cron Task/Job - MacOs](rules/macos/process_creation/proc_creation_macos_schedule_task_job_cron.kql) | medium | execution, persistence, privilege-escalation, T1053.003 | DeviceProcessEvents |
| [Security Software Discovery - MacOs](rules/macos/process_creation/proc_creation_macos_security_software_discovery.kql) | medium | discovery, T1518.001 | DeviceProcessEvents |
| [Suspicious Browser Child Process - MacOS](rules/macos/process_creation/proc_creation_macos_susp_browser_child_process.kql) | medium | initial-access, execution, T1189, T1203, T1059 | DeviceProcessEvents |
| [Suspicious Execution via macOS Script Editor](rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.kql) | medium | defense-impairment, T1566, T1566.002, initial-access, T1059, T1059.002, T1204, T1204.001, execution, persistence, T1553 | DeviceProcessEvents |
| [Potential Discovery Activity Using Find - MacOS](rules/macos/process_creation/proc_creation_macos_susp_find_execution.kql) | medium | discovery, T1083 | DeviceProcessEvents |
| [Suspicious History File Operations](rules/macos/process_creation/proc_creation_macos_susp_histfile_operations.kql) | medium | credential-access, T1552.003 | DeviceProcessEvents |
| [Potential In-Memory Download And Compile Of Payloads](rules/macos/process_creation/proc_creation_macos_susp_in_memory_download_and_compile.kql) | medium | command-and-control, execution, T1059.007, T1105 | DeviceProcessEvents |
| [Suspicious MacOS Firmware Activity](rules/macos/process_creation/proc_creation_macos_susp_macos_firmware_activity.kql) | medium | impact | DeviceProcessEvents |
| [Osacompile Execution By Potentially Suspicious Applet/Osascript](rules/macos/process_creation/proc_creation_macos_suspicious_applet_behaviour.kql) | medium | execution, T1059.002 | DeviceProcessEvents |
| [System Information Discovery Using sw_vers](rules/macos/process_creation/proc_creation_macos_swvers_discovery.kql) | medium | discovery, T1082 | DeviceProcessEvents |
| [User Added To Admin Group Via Sysadminctl](rules/macos/process_creation/proc_creation_macos_sysadminctl_add_user_to_admin_group.kql) | medium | persistence, initial-access, privilege-escalation, stealth, T1078.003 | DeviceProcessEvents |
| [System Information Discovery Via Sysctl - MacOS](rules/macos/process_creation/proc_creation_macos_sysctl_discovery.kql) | medium | stealth, T1497.001, discovery, T1082 | DeviceProcessEvents |
| [System Information Discovery Using System_Profiler](rules/macos/process_creation/proc_creation_macos_system_profiler_discovery.kql) | medium | discovery, stealth, T1082, T1497.001 | DeviceProcessEvents |
| [Potential Base64 Decoded From Images](rules/macos/process_creation/proc_creation_macos_tail_base64_decode_from_image.kql) | high | stealth, T1140 | DeviceProcessEvents |
| [Time Machine Backup Deletion Attempt Via Tmutil - MacOS](rules/macos/process_creation/proc_creation_macos_tmutil_delete_backup.kql) | medium | impact, T1490 | DeviceProcessEvents |
| [Time Machine Backup Disabled Via Tmutil - MacOS](rules/macos/process_creation/proc_creation_macos_tmutil_disable_backup.kql) | medium | impact, T1490 | DeviceProcessEvents |
| [New File Exclusion Added To Time Machine Via Tmutil - MacOS](rules/macos/process_creation/proc_creation_macos_tmutil_exclude_file_from_backup.kql) | medium | impact, T1490 | DeviceProcessEvents |
| [Potential WizardUpdate Malware Infection](rules/macos/process_creation/proc_creation_macos_wizardupdate_malware_infection.kql) | high | command-and-control | DeviceProcessEvents |
| [Potential XCSSET Malware Infection](rules/macos/process_creation/proc_creation_macos_xcsset_malware_infection.kql) | medium | command-and-control | DeviceProcessEvents |
| [Azure AD Health Monitoring Agent Registry Keys Access](rules/windows/builtin/security/win_security_aadhealth_mon_agent_regkey_access.kql) | medium | discovery, T1012 | DeviceRegistryEvents |
| [Azure AD Health Service Agents Registry Keys Access](rules/windows/builtin/security/win_security_aadhealth_svc_agent_regkey_access.kql) | medium | discovery, T1012 | DeviceRegistryEvents |
| [Processes Accessing the Microphone and Webcam](rules/windows/builtin/security/win_security_camera_microphone_access.kql) | medium | collection, T1123 | DeviceRegistryEvents |
| [WCE wceaux.dll Access](rules/windows/builtin/security/win_security_mal_wceaux_dll.kql) | critical | credential-access, T1003, S0005 | DeviceRegistryEvents |
| [SAM Registry Hive Handle Request](rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.kql) | high | discovery, T1012, credential-access, T1552.002 | DeviceRegistryEvents |
| [Potential Secure Deletion with SDelete](rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.kql) | medium | impact, stealth, defense-impairment, T1070.004, T1027.005, T1485, T1553.002, S0195 | DeviceRegistryEvents |
| [SysKey Registry Keys Access](rules/windows/builtin/security/win_security_syskey_registry_access.kql) | high | discovery, T1012 | DeviceRegistryEvents |
| [Suspicious Teams Application Related ObjectAcess Event](rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.kql) | high | credential-access, T1528 | DeviceRegistryEvents |
| [Windows Defender Exclusion List Modified](rules/windows/builtin/security/win_security_windows_defender_exclusions_registry_modified.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [WMI Persistence - Security](rules/windows/builtin/security/win_security_wmi_persistence.kql) | medium | persistence, privilege-escalation, T1546.003 | DeviceRegistryEvents |
| [Unusual File Modification by dns.exe](rules/windows/file/file_change/file_change_win_unusual_modification_by_dns_exe.kql) | high | persistence, initial-access, T1133 | DeviceFileEvents |
| [Backup Files Deleted](rules/windows/file/file_delete/file_delete_win_delete_backup_file.kql) | medium | impact, T1490 | DeviceFileEvents |
| [EventLog EVTX File Deleted](rules/windows/file/file_delete/file_delete_win_delete_event_log_files.kql) | medium | stealth, T1070 | DeviceFileEvents |
| [Exchange PowerShell Cmdlet History Deleted](rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.kql) | high | stealth, T1070 | DeviceFileEvents |
| [IIS WebServer Access Logs Deleted](rules/windows/file/file_delete/file_delete_win_delete_iis_access_logs.kql) | medium | stealth, T1070 | DeviceFileEvents |
| [PowerShell Console History Logs Deleted](rules/windows/file/file_delete/file_delete_win_delete_powershell_command_history.kql) | medium | stealth, T1070 | DeviceFileEvents |
| [Prefetch File Deleted](rules/windows/file/file_delete/file_delete_win_delete_prefetch.kql) | high | stealth, T1070.004 | DeviceFileEvents |
| [Tomcat WebServer Logs Deleted](rules/windows/file/file_delete/file_delete_win_delete_tomcat_logs.kql) | medium | stealth, T1070 | DeviceFileEvents |
| [File Deleted Via Sysinternals SDelete](rules/windows/file/file_delete/file_delete_win_sysinternals_sdelete_file_deletion.kql) | medium | stealth, T1070.004 | DeviceFileEvents |
| [Unusual File Deletion by Dns.exe](rules/windows/file/file_delete/file_delete_win_unusual_deletion_by_dns_exe.kql) | high | persistence, initial-access, T1133 | DeviceFileEvents |
| [ADS Zone.Identifier Deleted By Uncommon Application](rules/windows/file/file_delete/file_delete_win_zone_identifier_ads_uncommon.kql) | medium | stealth, T1070.004 | DeviceFileEvents |
| [ADSI-Cache File Creation By Uncommon Tool](rules/windows/file/file_event/file_event_win_adsi_cache_creation_by_uncommon_tool.kql) | medium | T1001.003, command-and-control | DeviceFileEvents |
| [Advanced IP Scanner - File Event](rules/windows/file/file_event/file_event_win_advanced_ip_scanner.kql) | medium | discovery, T1046 | DeviceFileEvents |
| [Anydesk Temporary Artefact](rules/windows/file/file_event/file_event_win_anydesk_artefact.kql) | medium | command-and-control, T1219.002 | DeviceFileEvents |
| [Suspicious Binary Writes Via AnyDesk](rules/windows/file/file_event/file_event_win_anydesk_writing_susp_binaries.kql) | high | command-and-control, T1219.002 | DeviceFileEvents |
| [Assembly DLL Creation Via AspNetCompiler](rules/windows/file/file_event/file_event_win_aspnet_temp_files.kql) | medium | execution | DeviceFileEvents |
| [BloodHound Collection Files](rules/windows/file/file_event/file_event_win_bloodhound_collection.kql) | high | discovery, T1087.001, T1087.002, T1482, T1069.001, T1069.002, execution, T1059.001 | DeviceFileEvents |
| [EVTX Created In Uncommon Location](rules/windows/file/file_event/file_event_win_create_evtx_non_common_locations.kql) | medium | defense-impairment, T1685.001 | DeviceFileEvents |
| [Creation Of Non-Existent System DLL](rules/windows/file/file_event/file_event_win_create_non_existent_dlls.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceFileEvents |
| [New Custom Shim Database Created](rules/windows/file/file_event/file_event_win_creation_new_shim_database.kql) | medium | privilege-escalation, persistence, T1547.009 | DeviceFileEvents |
| [Suspicious Screensaver Binary File Creation](rules/windows/file/file_event/file_event_win_creation_scr_binary_file.kql) | medium | privilege-escalation, persistence, T1546.002 | DeviceFileEvents |
| [Files With System DLL Name In Unsuspected Locations](rules/windows/file/file_event/file_event_win_creation_system_dll_files.kql) | medium | stealth, T1036.005 | DeviceFileEvents |
| [Files With System Process Name In Unsuspected Locations](rules/windows/file/file_event/file_event_win_creation_system_file.kql) | medium | stealth, T1036.005 | DeviceFileEvents |
| [Creation Exe for Service with Unquoted Path](rules/windows/file/file_event/file_event_win_creation_unquoted_service_path.kql) | high | privilege-escalation, persistence, T1547.009 | DeviceFileEvents |
| [Cred Dump Tools Dropped Files](rules/windows/file/file_event/file_event_win_cred_dump_tools_dropped_files.kql) | high | credential-access, T1003.001, T1003.002, T1003.003, T1003.004, T1003.005 | DeviceFileEvents |
| [WScript or CScript Dropper - File](rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.kql) | high | execution, T1059.005, T1059.007 | DeviceFileEvents |
| [CSExec Service File Creation](rules/windows/file/file_event/file_event_win_csexec_service.kql) | medium | execution, T1569.002, S0029 | DeviceFileEvents |
| [Potential DCOM InternetExplorer.Application DLL Hijack](rules/windows/file/file_event/file_event_win_dcom_iertutil_dll_hijack.kql) | critical | lateral-movement, T1021.002, T1021.003 | DeviceFileEvents |
| [Desktop.INI Created by Uncommon Process](rules/windows/file/file_event/file_event_win_desktop_ini_created_by_uncommon_process.kql) | medium | privilege-escalation, persistence, T1547.009 | DeviceFileEvents |
| [DLL Search Order Hijackig Via Additional Space in Path](rules/windows/file/file_event/file_event_win_dll_sideloading_space_path.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceFileEvents |
| [Potentially Suspicious DMP/HDMP File Creation](rules/windows/file/file_event/file_event_win_dump_file_susp_creation.kql) | medium | stealth | DeviceFileEvents |
| [Potential Persistence Attempt Via ErrorHandler.Cmd](rules/windows/file/file_event/file_event_win_errorhandler_persistence.kql) | medium | persistence | DeviceFileEvents |
| [Suspicious ASPX File Drop by Exchange](rules/windows/file/file_event/file_event_win_exchange_webshell_drop.kql) | high | persistence, T1505.003 | DeviceFileEvents |
| [Suspicious File Drop by Exchange](rules/windows/file/file_event/file_event_win_exchange_webshell_drop_suspicious.kql) | medium | persistence, T1190, initial-access, T1505.003 | DeviceFileEvents |
| [GoToAssist Temporary Installation Artefact](rules/windows/file/file_event/file_event_win_gotoopener_artefact.kql) | medium | command-and-control, T1219.002 | DeviceFileEvents |
| [HackTool - CrackMapExec File Indicators](rules/windows/file/file_event/file_event_win_hktl_crackmapexec_indicators.kql) | high | credential-access, T1003.001 | DeviceFileEvents |
| [HackTool - Dumpert Process Dumper Default File](rules/windows/file/file_event/file_event_win_hktl_dumpert.kql) | critical | credential-access, T1003.001 | DeviceFileEvents |
| [HackTool - Typical HiveNightmare SAM File Export](rules/windows/file/file_event/file_event_win_hktl_hivenightmare_file_exports.kql) | high | credential-access, T1552.001 | DeviceFileEvents |
| [HackTool - Inveigh Execution Artefacts](rules/windows/file/file_event/file_event_win_hktl_inveigh_artefacts.kql) | critical | command-and-control, T1219.002 | DeviceFileEvents |
| [HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators](rules/windows/file/file_event/file_event_win_hktl_krbrelay_remote_ioc.kql) | high | command-and-control, T1219.002 | DeviceFileEvents |
| [HackTool - Mimikatz Kirbi File Creation](rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.kql) | critical | credential-access, T1558 | DeviceFileEvents |
| [HackTool - NPPSpy Hacktool Usage](rules/windows/file/file_event/file_event_win_hktl_nppspy.kql) | high | credential-access | DeviceFileEvents |
| [HackTool - Powerup Write Hijack DLL](rules/windows/file/file_event/file_event_win_hktl_powerup_dllhijacking.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceFileEvents |
| [HackTool - QuarksPwDump Dump File](rules/windows/file/file_event/file_event_win_hktl_quarkspw_filedump.kql) | critical | credential-access, T1003.002 | DeviceFileEvents |
| [HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump](rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.kql) | high | credential-access, T1003 | DeviceFileEvents |
| [HackTool - SafetyKatz Dump Indicator](rules/windows/file/file_event/file_event_win_hktl_safetykatz.kql) | high | credential-access, T1003.001 | DeviceFileEvents |
| [Potential Initial Access via DLL Search Order Hijacking](rules/windows/file/file_event/file_event_win_initial_access_dll_search_order_hijacking.kql) | medium | privilege-escalation, persistence, execution, stealth, T1566, T1566.001, initial-access, T1574, T1574.001 | DeviceFileEvents |
| [Installation of TeamViewer Desktop](rules/windows/file/file_event/file_event_win_install_teamviewer_desktop.kql) | medium | command-and-control, T1219.002 | DeviceFileEvents |
| [Malicious DLL File Dropped in the Teams or OneDrive Folder](rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceFileEvents |
| [ISO File Created Within Temp Folders](rules/windows/file/file_event/file_event_win_iso_file_mount.kql) | high | initial-access, T1566.001 | DeviceFileEvents |
| [ISO or Image Mount Indicator in Recent Files](rules/windows/file/file_event/file_event_win_iso_file_recent.kql) | medium | initial-access, T1566.001 | DeviceFileEvents |
| [GatherNetworkInfo.VBS Reconnaissance Script Output](rules/windows/file/file_event/file_event_win_lolbin_gather_network_info_script_output.kql) | medium | discovery | DeviceFileEvents |
| [LSASS Process Memory Dump Files](rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.kql) | high | credential-access, T1003.001 | DeviceFileEvents |
| [LSASS Process Dump Artefact In CrashDumps Folder](rules/windows/file/file_event/file_event_win_lsass_shtinkering.kql) | high | credential-access, T1003.001 | DeviceFileEvents |
| [WerFault LSASS Process Memory Dump](rules/windows/file/file_event/file_event_win_lsass_werfault_dump.kql) | high | credential-access, T1003.001 | DeviceFileEvents |
| [Adwind RAT / JRAT File Artifact](rules/windows/file/file_event/file_event_win_mal_adwind.kql) | high | execution, T1059.005, T1059.007 | DeviceFileEvents |
| [Octopus Scanner Malware](rules/windows/file/file_event/file_event_win_mal_octopus_scanner.kql) | high | initial-access, T1195, T1195.001 | DeviceFileEvents |
| [File Creation In Suspicious Directory By Msdt.EXE](rules/windows/file/file_event/file_event_win_msdt_susp_directories.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceFileEvents |
| [Uncommon File Creation By Mysql Daemon Process](rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.kql) | high | stealth | DeviceFileEvents |
| [Suspicious File Creation In Uncommon AppData Folder](rules/windows/file/file_event/file_event_win_new_files_in_uncommon_appdata_folder.kql) | high | execution, stealth | DeviceFileEvents |
| [SCR File Write Event](rules/windows/file/file_event/file_event_win_new_scr_file.kql) | medium | stealth, T1218.011 | DeviceFileEvents |
| [Potential Persistence Via Notepad++ Plugins](rules/windows/file/file_event/file_event_win_notepad_plus_plus_persistence.kql) | medium | persistence | DeviceFileEvents |
| [NTDS.DIT Creation By Uncommon Parent Process](rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_parent_process.kql) | high | credential-access, T1003.003 | DeviceFileEvents |
| [NTDS.DIT Creation By Uncommon Process](rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_process.kql) | high | credential-access, T1003.002, T1003.003 | DeviceFileEvents |
| [NTDS Exfiltration Filename Patterns](rules/windows/file/file_event/file_event_win_ntds_exfil_tools.kql) | high | credential-access, T1003.003 | DeviceFileEvents |
| [Potential Persistence Via Microsoft Office Add-In](rules/windows/file/file_event/file_event_win_office_addin_persistence.kql) | high | persistence, T1137.006 | DeviceFileEvents |
| [Office Macro File Creation From Suspicious Process](rules/windows/file/file_event/file_event_win_office_macro_files_from_susp_process.kql) | high | initial-access, T1566.001 | DeviceFileEvents |
| [OneNote Attachment File Dropped In Suspicious Location](rules/windows/file/file_event/file_event_win_office_onenote_files_in_susp_locations.kql) | medium | stealth | DeviceFileEvents |
| [Suspicious File Created Via OneNote Application](rules/windows/file/file_event/file_event_win_office_onenote_susp_dropped_files.kql) | high | stealth | DeviceFileEvents |
| [New Outlook Macro Created](rules/windows/file/file_event/file_event_win_office_outlook_macro_creation.kql) | medium | privilege-escalation, persistence, command-and-control, T1137, T1008, T1546 | DeviceFileEvents |
| [Potential Persistence Via Outlook Form](rules/windows/file/file_event/file_event_win_office_outlook_newform.kql) | high | persistence, T1137.003 | DeviceFileEvents |
| [Suspicious Outlook Macro Created](rules/windows/file/file_event/file_event_win_office_outlook_susp_macro_creation.kql) | high | privilege-escalation, persistence, command-and-control, T1137, T1008, T1546 | DeviceFileEvents |
| [Publisher Attachment File Dropped In Suspicious Location](rules/windows/file/file_event/file_event_win_office_publisher_files_in_susp_locations.kql) | medium | stealth | DeviceFileEvents |
| [Potential Persistence Via Microsoft Office Startup Folder](rules/windows/file/file_event/file_event_win_office_startup_persistence.kql) | high | persistence, T1137 | DeviceFileEvents |
| [File With Uncommon Extension Created By An Office Application](rules/windows/file/file_event/file_event_win_office_susp_file_extension.kql) | high | T1204.002, execution | DeviceFileEvents |
| [Uncommon File Created In Office Startup Folder](rules/windows/file/file_event/file_event_win_office_uncommon_file_startup.kql) | high | resource-development, T1587.001 | DeviceFileEvents |
| [PCRE.NET Package Temp Files](rules/windows/file/file_event/file_event_win_pcre_net_temp_file.kql) | high | execution, T1059 | DeviceFileEvents |
| [Suspicious File Created In PerfLogs](rules/windows/file/file_event/file_event_win_perflogs_susp_files.kql) | medium | execution, T1059 | DeviceFileEvents |
| [Potential Binary Or Script Dropper Via PowerShell](rules/windows/file/file_event/file_event_win_powershell_drop_binary_or_script.kql) | medium | persistence | DeviceFileEvents |
| [Malicious PowerShell Scripts - FileCreation](rules/windows/file/file_event/file_event_win_powershell_exploit_scripts.kql) | high | execution, T1059.001 | DeviceFileEvents |
| [Potential Suspicious PowerShell Module File Created](rules/windows/file/file_event/file_event_win_powershell_module_susp_creation.kql) | medium | persistence | DeviceFileEvents |
| [PowerShell Module File Created By Non-PowerShell Process](rules/windows/file/file_event/file_event_win_powershell_module_uncommon_creation.kql) | medium | persistence | DeviceFileEvents |
| [Potential Startup Shortcut Persistence Via PowerShell.EXE](rules/windows/file/file_event/file_event_win_powershell_startup_shortcuts.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceFileEvents |
| [PSScriptPolicyTest Creation By Uncommon Process](rules/windows/file/file_event/file_event_win_ps_script_policy_test_creation_by_uncommon_process.kql) | medium | stealth | DeviceFileEvents |
| [Rclone Config File Creation](rules/windows/file/file_event/file_event_win_rclone_config_files.kql) | medium | exfiltration, T1567.002 | DeviceFileEvents |
| [.RDP File Created By Uncommon Application](rules/windows/file/file_event/file_event_win_rdp_file_susp_creation.kql) | high | stealth | DeviceFileEvents |
| [Potential Winnti Dropper Activity](rules/windows/file/file_event/file_event_win_redmimicry_winnti_filedrop.kql) | high | stealth, T1027 | DeviceFileEvents |
| [PDF File Created By RegEdit.EXE](rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.kql) | high | stealth | DeviceFileEvents |
| [RemCom Service File Creation](rules/windows/file/file_event/file_event_win_remcom_service.kql) | medium | execution, T1569.002, S0029 | DeviceFileEvents |
| [ScreenConnect Temporary Installation Artefact](rules/windows/file/file_event/file_event_win_remote_access_tools_screenconnect_artefact.kql) | medium | command-and-control, T1219.002 | DeviceFileEvents |
| [Potential RipZip Attack on Startup Folder](rules/windows/file/file_event/file_event_win_ripzip_attack.kql) | high | privilege-escalation, persistence, T1547 | DeviceFileEvents |
| [Potential SAM Database Dump](rules/windows/file/file_event/file_event_win_sam_dump.kql) | high | credential-access, T1003.002 | DeviceFileEvents |
| [Self Extraction Directive File Created In Potentially Suspicious Location](rules/windows/file/file_event/file_event_win_sed_file_creation.kql) | medium | stealth, T1218 | DeviceFileEvents |
| [Windows Shell/Scripting Application File Write to Suspicious Folder](rules/windows/file/file_event/file_event_win_shell_write_susp_directory.kql) | high | execution, T1059 | DeviceFileEvents |
| [Windows Binaries Write Suspicious Extensions](rules/windows/file/file_event/file_event_win_shell_write_susp_files_extensions.kql) | high | stealth, T1036 | DeviceFileEvents |
| [Startup Folder File Write](rules/windows/file/file_event/file_event_win_startup_folder_file_write.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceFileEvents |
| [Suspicious Creation with Colorcpl](rules/windows/file/file_event/file_event_win_susp_colorcpl.kql) | high | stealth, T1564 | DeviceFileEvents |
| [Created Files by Microsoft Sync Center](rules/windows/file/file_event/file_event_win_susp_creation_by_mobsync.kql) | medium | privilege-escalation, stealth, T1055, T1218, execution | DeviceFileEvents |
| [Suspicious Files in Default GPO Folder](rules/windows/file/file_event/file_event_win_susp_default_gpo_dir_write.kql) | medium | stealth, T1036.005 | DeviceFileEvents |
| [Suspicious Desktopimgdownldr Target File](rules/windows/file/file_event/file_event_win_susp_desktopimgdownldr_file.kql) | high | command-and-control, T1105 | DeviceFileEvents |
| [Creation of a Diagcab](rules/windows/file/file_event/file_event_win_susp_diagcab.kql) | medium | resource-development | DeviceFileEvents |
| [Suspicious Double Extension Files](rules/windows/file/file_event/file_event_win_susp_double_extension.kql) | high | stealth, T1036.007 | DeviceFileEvents |
| [DPAPI Backup Keys And Certificate Export Activity IOC](rules/windows/file/file_event/file_event_win_susp_dpapi_backup_and_cert_export_ioc.kql) | high | credential-access, T1555, T1552.004 | DeviceFileEvents |
| [Suspicious MSExchangeMailboxReplication ASPX Write](rules/windows/file/file_event/file_event_win_susp_exchange_aspx_write.kql) | high | initial-access, T1190, persistence, T1505.003 | DeviceFileEvents |
| [Suspicious Executable File Creation](rules/windows/file/file_event/file_event_win_susp_executable_creation.kql) | high | stealth, T1564 | DeviceFileEvents |
| [Suspicious Get-Variable.exe Creation](rules/windows/file/file_event/file_event_win_susp_get_variable.kql) | high | privilege-escalation, persistence, stealth, T1546, T1027 | DeviceFileEvents |
| [Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream](rules/windows/file/file_event/file_event_win_susp_hidden_dir_index_allocation.kql) | medium | stealth, T1564.004 | DeviceFileEvents |
| [Potential Homoglyph Attack Using Lookalike Characters in Filename](rules/windows/file/file_event/file_event_win_susp_homoglyph_filename.kql) | medium | stealth, T1036, T1036.003 | DeviceFileEvents |
| [Legitimate Application Dropped Archive](rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_archive.kql) | high | stealth, T1218 | DeviceFileEvents |
| [Legitimate Application Dropped Executable](rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_exe.kql) | high | stealth, T1218 | DeviceFileEvents |
| [Legitimate Application Dropped Script](rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_script.kql) | high | stealth, T1218 | DeviceFileEvents |
| [Suspicious LNK Double Extension File Created](rules/windows/file/file_event/file_event_win_susp_lnk_double_extension.kql) | medium | stealth, T1036.007 | DeviceFileEvents |
| [PowerShell Profile Modification](rules/windows/file/file_event/file_event_win_susp_powershell_profile.kql) | medium | persistence, privilege-escalation, T1546.013 | DeviceFileEvents |
| [Suspicious PROCEXP152.sys File Created In TMP](rules/windows/file/file_event/file_event_win_susp_procexplorer_driver_created_in_tmp_folder.kql) | medium | defense-impairment, T1685 | DeviceFileEvents |
| [Suspicious File Creation Activity From Fake Recycle.Bin Folder](rules/windows/file/file_event/file_event_win_susp_recycle_bin_fake_exec.kql) | high | persistence, stealth | DeviceFileEvents |
| [Potential File Extension Spoofing Using Right-to-Left Override](rules/windows/file/file_event/file_event_win_susp_right_to_left_override_extension_spoofing.kql) | high | execution, stealth, T1036.002 | DeviceFileEvents |
| [Drop Binaries Into Spool Drivers Color Folder](rules/windows/file/file_event/file_event_win_susp_spool_drivers_color_drop.kql) | medium | stealth | DeviceFileEvents |
| [Suspicious Startup Folder Persistence](rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.kql) | high | privilege-escalation, execution, T1204.002, persistence, T1547.001 | DeviceFileEvents |
| [Suspicious Interactive PowerShell as SYSTEM](rules/windows/file/file_event/file_event_win_susp_system_interactive_powershell.kql) | high | execution, T1059.001 | DeviceFileEvents |
| [Suspicious Scheduled Task Write to System32 Tasks](rules/windows/file/file_event/file_event_win_susp_task_write.kql) | high | privilege-escalation, persistence, execution, T1053 | DeviceFileEvents |
| [TeamViewer Remote Session](rules/windows/file/file_event/file_event_win_susp_teamviewer_remote_session.kql) | medium | command-and-control, T1219.002 | DeviceFileEvents |
| [VsCode Powershell Profile Modification](rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.kql) | medium | persistence, privilege-escalation, T1546.013 | DeviceFileEvents |
| [Windows Terminal Profile Settings Modification By Uncommon Process](rules/windows/file/file_event/file_event_win_susp_windows_terminal_profile.kql) | medium | privilege-escalation, persistence, T1547.015 | DeviceFileEvents |
| [WinSxS Executable File Creation By Non-System Process](rules/windows/file/file_event/file_event_win_susp_winsxs_binary_creation.kql) | medium | execution | DeviceFileEvents |
| [LiveKD Kernel Memory Dump File Created](rules/windows/file/file_event/file_event_win_sysinternals_livekd_default_dump_name.kql) | high | privilege-escalation, stealth | DeviceFileEvents |
| [LiveKD Driver Creation](rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver.kql) | medium | privilege-escalation, stealth | DeviceFileEvents |
| [LiveKD Driver Creation By Uncommon Process](rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver_susp_creation.kql) | high | privilege-escalation, stealth | DeviceFileEvents |
| [Process Explorer Driver Creation By Non-Sysinternals Binary](rules/windows/file/file_event/file_event_win_sysinternals_procexp_driver_susp_creation.kql) | high | persistence, privilege-escalation, T1068 | DeviceFileEvents |
| [Process Monitor Driver Creation By Non-Sysinternals Binary](rules/windows/file/file_event/file_event_win_sysinternals_procmon_driver_susp_creation.kql) | medium | persistence, privilege-escalation, T1068 | DeviceFileEvents |
| [PSEXEC Remote Execution File Artefact](rules/windows/file/file_event/file_event_win_sysinternals_psexec_service_key.kql) | high | lateral-movement, privilege-escalation, execution, persistence, T1136.002, T1543.003, T1570, S0029 | DeviceFileEvents |
| [Potential Privilege Escalation Attempt Via .Exe.Local Technique](rules/windows/file/file_event/file_event_win_system32_local_folder_privilege_escalation.kql) | high | persistence, privilege-escalation, stealth | DeviceFileEvents |
| [LSASS Process Memory Dump Creation Via Taskmgr.EXE](rules/windows/file/file_event/file_event_win_taskmgr_lsass_dump.kql) | high | credential-access, T1003.001 | DeviceFileEvents |
| [Hijack Legit RDP Session to Move Laterally](rules/windows/file/file_event/file_event_win_tsclient_filewrite_startup.kql) | high | command-and-control, T1219.002 | DeviceFileEvents |
| [UAC Bypass Using Consent and Comctl32 - File](rules/windows/file/file_event/file_event_win_uac_bypass_consent_comctl32.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Using .NET Code Profiler on MMC](rules/windows/file/file_event/file_event_win_uac_bypass_dotnet_profiler.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Using EventVwr](rules/windows/file/file_event/file_event_win_uac_bypass_eventvwr.kql) | high | privilege-escalation, stealth | DeviceFileEvents |
| [UAC Bypass Using IDiagnostic Profile - File](rules/windows/file/file_event/file_event_win_uac_bypass_idiagnostic_profile.kql) | high | execution, privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Using IEInstal - File](rules/windows/file/file_event/file_event_win_uac_bypass_ieinstal.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Using MSConfig Token Modification - File](rules/windows/file/file_event/file_event_win_uac_bypass_msconfig_gui.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Using NTFS Reparse Point - File](rules/windows/file/file_event/file_event_win_uac_bypass_ntfs_reparse_point.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Abusing Winsat Path Parsing - File](rules/windows/file/file_event/file_event_win_uac_bypass_winsat.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [UAC Bypass Using Windows Media Player - File](rules/windows/file/file_event/file_event_win_uac_bypass_wmp.kql) | high | privilege-escalation, T1548.002 | DeviceFileEvents |
| [VHD Image Download Via Browser](rules/windows/file/file_event/file_event_win_vhd_download_via_browsers.kql) | medium | resource-development, T1587.001 | DeviceFileEvents |
| [Visual Studio Code Tunnel Remote File Creation](rules/windows/file/file_event/file_event_win_vscode_tunnel_remote_creation_artefacts.kql) | medium | command-and-control | DeviceFileEvents |
| [Renamed VsCode Code Tunnel Execution - File Indicator](rules/windows/file/file_event/file_event_win_vscode_tunnel_renamed_execution.kql) | high | command-and-control | DeviceFileEvents |
| [Potential Webshell Creation On Static Website](rules/windows/file/file_event/file_event_win_webshell_creation_detect.kql) | medium | persistence, T1505.003 | DeviceFileEvents |
| [Creation of WerFault.exe/Wer.dll in Unusual Folder](rules/windows/file/file_event/file_event_win_werfault_dll_hijacking.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceFileEvents |
| [AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File](rules/windows/file/file_event/file_event_win_winrm_awl_bypass.kql) | medium | stealth, T1216 | DeviceFileEvents |
| [WMI Persistence - Script Event Consumer File Write](rules/windows/file/file_event/file_event_win_wmi_persistence_script_event_consumer_write.kql) | high | privilege-escalation, T1546.003, persistence | DeviceFileEvents |
| [Wmiexec Default Output File](rules/windows/file/file_event/file_event_win_wmiexec_default_filename.kql) | critical | lateral-movement, execution, T1047 | DeviceFileEvents |
| [Wmiprvse Wbemcomn DLL Hijack - File](rules/windows/file/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.kql) | critical | execution, T1047, lateral-movement, T1021.002 | DeviceFileEvents |
| [UEFI Persistence Via Wpbbin - FileCreation](rules/windows/file/file_event/file_event_win_wpbbin_persistence.kql) | high | persistence, stealth, T1542.001 | DeviceFileEvents |
| [Writing Local Admin Share](rules/windows/file/file_event/file_event_win_writing_local_admin_share.kql) | medium | privilege-escalation, persistence, lateral-movement, T1546.002 | DeviceFileEvents |
| [Suspicious Appended Extension](rules/windows/file/file_rename/file_rename_win_ransomware.kql) | medium | impact, T1486 | DeviceFileEvents |
| [DLL Loaded From Suspicious Location Via Cmspt.EXE](rules/windows/image_load/image_load_cmstp_load_dll_from_susp_location.kql) | high | stealth, T1218.003 | DeviceImageLoadEvents |
| [Amsi.DLL Loaded Via LOLBIN Process](rules/windows/image_load/image_load_dll_amsi_suspicious_process.kql) | medium | defense-impairment | DeviceImageLoadEvents |
| [CredUI.DLL Loaded By Uncommon Process](rules/windows/image_load/image_load_dll_credui_uncommon_process_load.kql) | medium | credential-access, collection, T1056.002 | DeviceImageLoadEvents |
| [PCRE.NET Package Image Load](rules/windows/image_load/image_load_dll_pcre_dotnet_dll_load.kql) | high | execution, T1059 | DeviceImageLoadEvents |
| [Load Of RstrtMgr.DLL By A Suspicious Process](rules/windows/image_load/image_load_dll_rstrtmgr_suspicious_load.kql) | high | impact, defense-impairment, T1486, T1685 | DeviceImageLoadEvents |
| [Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE](rules/windows/image_load/image_load_dll_sdiageng_load_by_msdt.kql) | high | stealth, T1202 | DeviceImageLoadEvents |
| [PowerShell Core DLL Loaded By Non PowerShell Process](rules/windows/image_load/image_load_dll_system_management_automation_susp_load.kql) | medium | T1059.001, execution | DeviceImageLoadEvents |
| [Time Travel Debugging Utility Usage - Image](rules/windows/image_load/image_load_dll_tttracer_module_load.kql) | high | credential-access, stealth, T1218, T1003.001 | DeviceImageLoadEvents |
| [Suspicious Volume Shadow Copy VSS_PS.dll Load](rules/windows/image_load/image_load_dll_vss_ps_susp_load.kql) | high | impact, T1490 | DeviceImageLoadEvents |
| [Suspicious Volume Shadow Copy Vssapi.dll Load](rules/windows/image_load/image_load_dll_vssapi_susp_load.kql) | high | impact, T1490 | DeviceImageLoadEvents |
| [Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load](rules/windows/image_load/image_load_dll_vsstrace_susp_load.kql) | medium | impact, T1490 | DeviceImageLoadEvents |
| [HackTool - SILENTTRINITY Stager DLL Load](rules/windows/image_load/image_load_hktl_silenttrinity_stager.kql) | high | command-and-control, T1071 | DeviceImageLoadEvents |
| [Potential DCOM InternetExplorer.Application DLL Hijack - Image Load](rules/windows/image_load/image_load_iexplore_dcom_iertutil_dll_hijack.kql) | critical | lateral-movement, T1021.002, T1021.003 | DeviceImageLoadEvents |
| [DotNET Assembly DLL Loaded Via Office Application](rules/windows/image_load/image_load_office_dotnet_assembly_dll_load.kql) | medium | execution, T1204.002 | DeviceImageLoadEvents |
| [CLR DLL Loaded Via Office Applications](rules/windows/image_load/image_load_office_dotnet_clr_dll_load.kql) | medium | execution, T1204.002 | DeviceImageLoadEvents |
| [GAC DLL Loaded Via Office Applications](rules/windows/image_load/image_load_office_dotnet_gac_dll_load.kql) | high | execution, T1204.002 | DeviceImageLoadEvents |
| [Microsoft Excel Add-In Loaded From Uncommon Location](rules/windows/image_load/image_load_office_excel_xll_susp_load.kql) | medium | execution, T1204.002 | DeviceImageLoadEvents |
| [Microsoft VBA For Outlook Addin Loaded Via Outlook](rules/windows/image_load/image_load_office_outlook_outlvba_load.kql) | medium | execution, T1204.002 | DeviceImageLoadEvents |
| [PowerShell Core DLL Loaded Via Office Application](rules/windows/image_load/image_load_office_powershell_dll_load.kql) | medium | stealth | DeviceImageLoadEvents |
| [VBA DLL Loaded Via Office Application](rules/windows/image_load/image_load_office_vbadll_load.kql) | high | execution, T1204.002 | DeviceImageLoadEvents |
| [Remote DLL Load Via Rundll32.EXE](rules/windows/image_load/image_load_rundll32_remote_share_load.kql) | medium | execution, T1204.002 | DeviceImageLoadEvents |
| [WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load](rules/windows/image_load/image_load_scrcons_wmi_scripteventconsumer.kql) | medium | lateral-movement, privilege-escalation, persistence, T1546.003 | DeviceImageLoadEvents |
| [Abusable DLL Potential Sideloading From Suspicious Location](rules/windows/image_load/image_load_side_load_abused_dlls_susp_paths.kql) | high | execution, T1059 | DeviceImageLoadEvents |
| [Potential Antivirus Software DLL Sideloading](rules/windows/image_load/image_load_side_load_antivirus.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential appverifUI.DLL Sideloading](rules/windows/image_load/image_load_side_load_appverifui.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Aruba Network Service Potential DLL Sideloading](rules/windows/image_load/image_load_side_load_aruba_networks_virtual_intranet_access.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential AVKkid.DLL Sideloading](rules/windows/image_load/image_load_side_load_avkkid.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential CCleanerDU.DLL Sideloading](rules/windows/image_load/image_load_side_load_ccleaner_du.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential CCleanerReactivator.DLL Sideloading](rules/windows/image_load/image_load_side_load_ccleaner_reactivator.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Chrome Frame Helper DLL Sideloading](rules/windows/image_load/image_load_side_load_chrome_frame_helper.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Via ClassicExplorer32.dll](rules/windows/image_load/image_load_side_load_classicexplorer32.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Via comctl32.dll](rules/windows/image_load/image_load_side_load_comctl32.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Using Coregen.exe](rules/windows/image_load/image_load_side_load_coregen.kql) | medium | privilege-escalation, stealth, T1218, T1055 | DeviceImageLoadEvents |
| [System Control Panel Item Loaded From Uncommon Location](rules/windows/image_load/image_load_side_load_cpl_from_non_system_location.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Of DBGCORE.DLL](rules/windows/image_load/image_load_side_load_dbgcore.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Of DBGHELP.DLL](rules/windows/image_load/image_load_side_load_dbghelp.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Of DbgModel.DLL](rules/windows/image_load/image_load_side_load_dbgmodel.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential EACore.DLL Sideloading](rules/windows/image_load/image_load_side_load_eacore.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Edputil.DLL Sideloading](rules/windows/image_load/image_load_side_load_edputil.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential System DLL Sideloading From Non System Locations](rules/windows/image_load/image_load_side_load_from_non_system_location.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Goopdate.DLL Sideloading](rules/windows/image_load/image_load_side_load_goopdate.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE](rules/windows/image_load/image_load_side_load_gup_libcurl.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Iviewers.DLL Sideloading](rules/windows/image_load/image_load_side_load_iviewers.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Via JsSchHlp](rules/windows/image_load/image_load_side_load_jsschhlp.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Libvlc.DLL Sideloading](rules/windows/image_load/image_load_side_load_libvlc.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Mfdetours.DLL Sideloading](rules/windows/image_load/image_load_side_load_mfdetours.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Of MpSvc.DLL](rules/windows/image_load/image_load_side_load_mpsvc.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Of MsCorSvc.DLL](rules/windows/image_load/image_load_side_load_mscorsvc.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Microsoft Office DLL Sideload](rules/windows/image_load/image_load_side_load_office_dlls.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Rcdll.DLL Sideloading](rules/windows/image_load/image_load_side_load_rcdll.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential RjvPlatform.DLL Sideloading From Default Location](rules/windows/image_load/image_load_side_load_rjvplatform_default_location.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential RjvPlatform.DLL Sideloading From Non-Default Location](rules/windows/image_load/image_load_side_load_rjvplatform_non_default_location.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential RoboForm.DLL Sideloading](rules/windows/image_load/image_load_side_load_robform.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [DLL Sideloading Of ShellChromeAPI.DLL](rules/windows/image_load/image_load_side_load_shell_chrome_api.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential ShellDispatch.DLL Sideloading](rules/windows/image_load/image_load_side_load_shelldispatch.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential SmadHook.DLL Sideloading](rules/windows/image_load/image_load_side_load_smadhook.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential SolidPDFCreator.DLL Sideloading](rules/windows/image_load/image_load_side_load_solidpdfcreator.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Third Party Software DLL Sideloading](rules/windows/image_load/image_load_side_load_third_party.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Fax Service DLL Search Order Hijack](rules/windows/image_load/image_load_side_load_ualapi.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Vivaldi_elf.DLL Sideloading](rules/windows/image_load/image_load_side_load_vivaldi_elf.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential DLL Sideloading Via VMware Xfer](rules/windows/image_load/image_load_side_load_vmware_xfer.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Waveedit.DLL Sideloading](rules/windows/image_load/image_load_side_load_waveedit.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Wazuh Security Platform DLL Sideloading](rules/windows/image_load/image_load_side_load_wazuh.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential Mpclient.DLL Sideloading](rules/windows/image_load/image_load_side_load_windows_defender.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Potential WWlib.DLL Sideloading](rules/windows/image_load/image_load_side_load_wwlib.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [DLL Load By System Process From Suspicious Locations](rules/windows/image_load/image_load_susp_dll_load_system_process.kql) | medium | stealth, T1070 | DeviceImageLoadEvents |
| [DotNet CLR DLL Loaded By Scripting Applications](rules/windows/image_load/image_load_susp_script_dotnet_clr_dll_load.kql) | high | execution, privilege-escalation, stealth, T1055 | DeviceImageLoadEvents |
| [UAC Bypass Using Iscsicpl - ImageLoad](rules/windows/image_load/image_load_uac_bypass_iscsicpl.kql) | high | privilege-escalation, T1548.002 | DeviceImageLoadEvents |
| [UAC Bypass With Fake DLL](rules/windows/image_load/image_load_uac_bypass_via_dism.kql) | high | persistence, privilege-escalation, execution, stealth, T1548.002, T1574.001 | DeviceImageLoadEvents |
| [WMI Persistence - Command Line Event Consumer](rules/windows/image_load/image_load_wmi_persistence_commandline_event_consumer.kql) | high | privilege-escalation, T1546.003, persistence | DeviceImageLoadEvents |
| [WMIC Loading Scripting Libraries](rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.kql) | medium | stealth, T1220 | DeviceImageLoadEvents |
| [Wmiprvse Wbemcomn DLL Hijack](rules/windows/image_load/image_load_wmiprvse_wbemcomn_dll_hijack.kql) | high | execution, T1047, lateral-movement, T1021.002 | DeviceImageLoadEvents |
| [Suspicious WSMAN Provider Image Loads](rules/windows/image_load/image_load_wsman_provider_image_load.kql) | medium | execution, T1059.001, lateral-movement, T1021.003 | DeviceImageLoadEvents |
| [Network Connection Initiated By AddinUtil.EXE](rules/windows/network_connection/net_connection_win_addinutil_initiated.kql) | high | stealth, T1218 | DeviceNetworkEvents |
| [Uncommon Connection to Active Directory Web Services](rules/windows/network_connection/net_connection_win_adws_unusual_connection.kql) | medium | discovery, T1087 | DeviceNetworkEvents |
| [Outbound Network Connection Initiated By Cmstp.EXE](rules/windows/network_connection/net_connection_win_cmstp_initiated_connection.kql) | high | stealth, T1218.003 | DeviceNetworkEvents |
| [Outbound Network Connection Initiated By Microsoft Dialer](rules/windows/network_connection/net_connection_win_dialer_initiated_connection.kql) | high | execution, command-and-control, T1071.001 | DeviceNetworkEvents |
| [Network Connection Initiated To AzureWebsites.NET By Non-Browser Process](rules/windows/network_connection/net_connection_win_domain_azurewebsites.kql) | medium | command-and-control, T1102, T1102.001 | DeviceNetworkEvents |
| [Network Connection Initiated To BTunnels Domains](rules/windows/network_connection/net_connection_win_domain_btunnels.kql) | medium | exfiltration, command-and-control, T1567, T1572 | DeviceNetworkEvents |
| [Network Connection Initiated To Cloudflared Tunnels Domains](rules/windows/network_connection/net_connection_win_domain_cloudflared_communication.kql) | medium | exfiltration, command-and-control, T1567, T1572 | DeviceNetworkEvents |
| [Network Communication With Crypto Mining Pool](rules/windows/network_connection/net_connection_win_domain_crypto_mining_pools.kql) | high | impact, T1496 | DeviceNetworkEvents |
| [New Connection Initiated To Potential Dead Drop Resolver Domain](rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.kql) | high | command-and-control, T1102, T1102.001 | DeviceNetworkEvents |
| [Network Connection Initiated To DevTunnels Domain](rules/windows/network_connection/net_connection_win_domain_devtunnels.kql) | medium | exfiltration, command-and-control, T1567.001, T1572 | DeviceNetworkEvents |
| [Suspicious Dropbox API Usage](rules/windows/network_connection/net_connection_win_domain_dropbox_api.kql) | high | command-and-control, exfiltration, T1105, T1567.002 | DeviceNetworkEvents |
| [Suspicious Network Connection to IP Lookup Service APIs](rules/windows/network_connection/net_connection_win_domain_external_ip_lookup.kql) | medium | discovery, T1016 | DeviceNetworkEvents |
| [Communication To LocaltoNet Tunneling Service Initiated](rules/windows/network_connection/net_connection_win_domain_localtonet_tunnel.kql) | high | command-and-control, T1572, T1090, T1102 | DeviceNetworkEvents |
| [Process Initiated Network Connection To Ngrok Domain](rules/windows/network_connection/net_connection_win_domain_ngrok.kql) | high | exfiltration, command-and-control, T1567, T1572, T1102 | DeviceNetworkEvents |
| [Communication To Ngrok Tunneling Service Initiated](rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.kql) | high | exfiltration, command-and-control, T1567, T1568.002, T1572, T1090, T1102, S0508 | DeviceNetworkEvents |
| [Network Communication Initiated To Portmap.IO Domain](rules/windows/network_connection/net_connection_win_domain_portmap.kql) | medium | T1041, command-and-control, T1090.002, exfiltration | DeviceNetworkEvents |
| [Suspicious Non-Browser Network Communication With Telegram API](rules/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access.kql) | medium | command-and-control, exfiltration, T1102, T1567, T1105 | DeviceNetworkEvents |
| [Network Connection Initiated To Visual Studio Code Tunnels Domain](rules/windows/network_connection/net_connection_win_domain_vscode_tunnel_connection.kql) | medium | exfiltration, command-and-control, T1567, T1572 | DeviceNetworkEvents |
| [Network Connection Initiated By Eqnedt32.EXE](rules/windows/network_connection/net_connection_win_eqnedt.kql) | high | execution, T1203 | DeviceNetworkEvents |
| [Network Connection Initiated By IMEWDBLD.EXE](rules/windows/network_connection/net_connection_win_imewdbld.kql) | high | command-and-control, T1105 | DeviceNetworkEvents |
| [Network Connection Initiated Via Notepad.EXE](rules/windows/network_connection/net_connection_win_notepad.kql) | high | privilege-escalation, command-and-control, execution, stealth, T1055 | DeviceNetworkEvents |
| [Python Initiated Connection](rules/windows/network_connection/net_connection_win_python.kql) | medium | discovery, T1046 | DeviceNetworkEvents |
| [Outbound RDP Connections Over Non-Standard Tools](rules/windows/network_connection/net_connection_win_rdp_outbound_over_non_standard_tools.kql) | high | lateral-movement, T1021.001 | DeviceNetworkEvents |
| [RDP Over Reverse SSH Tunnel](rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.kql) | high | command-and-control, T1572, lateral-movement, T1021.001 | DeviceNetworkEvents |
| [RegAsm.EXE Initiating Network Connection To Public IP](rules/windows/network_connection/net_connection_win_regasm_network_activity.kql) | medium | stealth, T1218.009 | DeviceNetworkEvents |
| [Network Connection Initiated By Regsvr32.EXE](rules/windows/network_connection/net_connection_win_regsvr32_network_activity.kql) | medium | execution, stealth, T1559.001, T1218.010 | DeviceNetworkEvents |
| [Rundll32 Internet Connection](rules/windows/network_connection/net_connection_win_rundll32_net_connections.kql) | medium | stealth, T1218.011, execution | DeviceNetworkEvents |
| [Suspicious Network Connection Binary No CommandLine](rules/windows/network_connection/net_connection_win_susp_binary_no_cmdline.kql) | high | stealth | DeviceNetworkEvents |
| [Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder](rules/windows/network_connection/net_connection_win_susp_file_sharing_domains_susp_folders.kql) | high | command-and-control, T1105 | DeviceNetworkEvents |
| [Network Connection Initiated From Process Located In Potentially Suspicious Or Uncommon Location](rules/windows/network_connection/net_connection_win_susp_initiated_uncommon_or_suspicious_locations.kql) | high | command-and-control, T1105 | DeviceNetworkEvents |
| [Uncommon Outbound Kerberos Connection](rules/windows/network_connection/net_connection_win_susp_outbound_kerberos_connection.kql) | medium | credential-access, T1558, lateral-movement, T1550.003 | DeviceNetworkEvents |
| [Microsoft Sync Center Suspicious Network Connections](rules/windows/network_connection/net_connection_win_susp_outbound_mobsync_connection.kql) | medium | privilege-escalation, stealth, T1055, T1218, execution | DeviceNetworkEvents |
| [Outbound Network Connection To Public IP Via Winlogon](rules/windows/network_connection/net_connection_win_winlogon_net_connections.kql) | medium | execution, command-and-control, stealth, T1218.011 | DeviceNetworkEvents |
| [Local Network Connection Initiated By Script Interpreter](rules/windows/network_connection/net_connection_win_wscript_cscript_local_connection.kql) | medium | command-and-control, T1105 | DeviceNetworkEvents |
| [Outbound Network Connection Initiated By Script Interpreter](rules/windows/network_connection/net_connection_win_wscript_cscript_outbound_connection.kql) | high | command-and-control, T1105 | DeviceNetworkEvents |
| [Potentially Suspicious Wuauclt Network Connection](rules/windows/network_connection/net_connection_win_wuauclt_network_connection.kql) | medium | stealth, T1218 | DeviceNetworkEvents |
| [7Zip Compressing Dump Files](rules/windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.kql) | medium | collection, T1560.001 | DeviceProcessEvents |
| [Compress Data and Lock With Password for Exfiltration With 7-ZIP](rules/windows/process_creation/proc_creation_win_7zip_password_compression.kql) | medium | collection, T1560.001 | DeviceProcessEvents |
| [Potential DLL Injection Via AccCheckConsole](rules/windows/process_creation/proc_creation_win_acccheckconsole_execution.kql) | medium | execution | DeviceProcessEvents |
| [Uncommon Child Process Of AddinUtil.EXE](rules/windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Uncommon AddinUtil.EXE CommandLine Execution](rules/windows/process_creation/proc_creation_win_addinutil_uncommon_cmdline.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [AddinUtil.EXE Execution From Uncommon Directory](rules/windows/process_creation/proc_creation_win_addinutil_uncommon_dir_exec.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential Adplus.EXE Abuse](rules/windows/process_creation/proc_creation_win_adplus_memory_dump.kql) | high | execution, credential-access, T1003.001 | DeviceProcessEvents |
| [AgentExecutor PowerShell Execution](rules/windows/process_creation/proc_creation_win_agentexecutor_potential_abuse.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious AgentExecutor PowerShell Execution](rules/windows/process_creation/proc_creation_win_agentexecutor_susp_usage.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Uncommon Child Process Of Appvlp.EXE](rules/windows/process_creation/proc_creation_win_appvlp_uncommon_child_process.kql) | medium | stealth, T1218, execution | DeviceProcessEvents |
| [AspNetCompiler Execution](rules/windows/process_creation/proc_creation_win_aspnet_compiler_exectuion.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [Suspicious Child Process of AspNetCompiler](rules/windows/process_creation/proc_creation_win_aspnet_compiler_susp_child_process.kql) | high | execution, stealth, T1127 | DeviceProcessEvents |
| [Potentially Suspicious ASP.NET Compilation Via AspNetCompiler](rules/windows/process_creation/proc_creation_win_aspnet_compiler_susp_paths.kql) | high | execution, stealth, T1127 | DeviceProcessEvents |
| [Interactive AT Job](rules/windows/process_creation/proc_creation_win_at_interactive_execution.kql) | high | persistence, execution, privilege-escalation, T1053.002 | DeviceProcessEvents |
| [Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE](rules/windows/process_creation/proc_creation_win_atbroker_uncommon_ats_execution.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Hiding Files with Attrib.exe](rules/windows/process_creation/proc_creation_win_attrib_hiding_files.kql) | medium | stealth, T1564.001 | DeviceProcessEvents |
| [Set Suspicious Files as System Files Using Attrib.EXE](rules/windows/process_creation/proc_creation_win_attrib_system_susp_paths.kql) | high | stealth, T1564.001 | DeviceProcessEvents |
| [Audit Policy Tampering Via NT Resource Kit Auditpol](rules/windows/process_creation/proc_creation_win_auditpol_nt_resource_kit_usage.kql) | high | defense-impairment, T1685.001 | DeviceProcessEvents |
| [Audit Policy Tampering Via Auditpol](rules/windows/process_creation/proc_creation_win_auditpol_susp_execution.kql) | high | defense-impairment, T1685.001 | DeviceProcessEvents |
| [Indirect Inline Command Execution Via Bash.EXE](rules/windows/process_creation/proc_creation_win_bash_command_execution.kql) | medium | stealth, T1202 | DeviceProcessEvents |
| [Indirect Command Execution From Script File Via Bash.EXE](rules/windows/process_creation/proc_creation_win_bash_file_execution.kql) | medium | stealth, T1202 | DeviceProcessEvents |
| [Boot Configuration Tampering Via Bcdedit.EXE](rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.kql) | high | impact, T1490 | DeviceProcessEvents |
| [Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE](rules/windows/process_creation/proc_creation_win_bcdedit_susp_execution.kql) | medium | stealth, T1070, persistence, T1542.003 | DeviceProcessEvents |
| [Data Export From MSSQL Table Via BCP.EXE](rules/windows/process_creation/proc_creation_win_bcp_export_data.kql) | medium | execution, exfiltration, T1048 | DeviceProcessEvents |
| [Suspicious Child Process Of BgInfo.EXE](rules/windows/process_creation/proc_creation_win_bginfo_suspicious_child_process.kql) | high | execution, stealth, T1059.005, T1218, T1202 | DeviceProcessEvents |
| [Uncommon Child Process Of BgInfo.EXE](rules/windows/process_creation/proc_creation_win_bginfo_uncommon_child_process.kql) | medium | execution, stealth, T1059.005, T1218, T1202 | DeviceProcessEvents |
| [File Download Via Bitsadmin](rules/windows/process_creation/proc_creation_win_bitsadmin_download.kql) | medium | persistence, execution, stealth, T1197, S0190, T1036.003, command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Download From Direct IP Via Bitsadmin](rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.kql) | high | persistence, execution, stealth, T1197, S0190, T1036.003 | DeviceProcessEvents |
| [Suspicious Download From File-Sharing Website Via Bitsadmin](rules/windows/process_creation/proc_creation_win_bitsadmin_download_file_sharing_domains.kql) | high | persistence, execution, stealth, T1197, S0190, T1036.003, command-and-control, T1105 | DeviceProcessEvents |
| [File With Suspicious Extension Downloaded Via Bitsadmin](rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.kql) | high | persistence, execution, stealth, T1197, S0190, T1036.003, command-and-control, T1105 | DeviceProcessEvents |
| [File Download Via Bitsadmin To A Suspicious Target Folder](rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.kql) | high | persistence, execution, stealth, T1197, S0190, T1036.003, command-and-control, T1105 | DeviceProcessEvents |
| [Monitoring For Persistence Via BITS](rules/windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.kql) | medium | persistence, execution, stealth, T1197 | DeviceProcessEvents |
| [Potential Data Stealing Via Chromium Headless Debugging](rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging.kql) | high | credential-access, collection, stealth, T1185, T1564.003 | DeviceProcessEvents |
| [File Download with Headless Browser](rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.kql) | high | command-and-control, stealth, T1105, T1564.003 | DeviceProcessEvents |
| [Chromium Browser Instance Executed With Custom Extension](rules/windows/process_creation/proc_creation_win_browsers_chromium_load_extension.kql) | medium | persistence, T1176.001 | DeviceProcessEvents |
| [Chromium Browser Headless Execution To Mockbin Like Site](rules/windows/process_creation/proc_creation_win_browsers_chromium_mockbin_abuse.kql) | high | execution | DeviceProcessEvents |
| [Suspicious Chromium Browser Instance Executed With Custom Extension](rules/windows/process_creation/proc_creation_win_browsers_chromium_susp_load_extension.kql) | high | persistence, T1176.001 | DeviceProcessEvents |
| [File Download From Browser Process Via Inline URL](rules/windows/process_creation/proc_creation_win_browsers_inline_file_download.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Browser Started with Remote Debugging](rules/windows/process_creation/proc_creation_win_browsers_remote_debugging.kql) | medium | credential-access, collection, T1185 | DeviceProcessEvents |
| [Tor Client/Browser Execution](rules/windows/process_creation/proc_creation_win_browsers_tor_execution.kql) | high | command-and-control, T1090.003 | DeviceProcessEvents |
| [Suspicious Calculator Usage](rules/windows/process_creation/proc_creation_win_calc_uncommon_exec.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Potential Binary Proxy Execution Via Cdb.EXE](rules/windows/process_creation/proc_creation_win_cdb_arbitrary_command_execution.kql) | medium | execution, stealth, T1106, T1218, T1127 | DeviceProcessEvents |
| [New Root Certificate Installed Via CertMgr.EXE](rules/windows/process_creation/proc_creation_win_certmgr_certificate_installation.kql) | medium | defense-impairment, T1553.004 | DeviceProcessEvents |
| [File Download via CertOC.EXE](rules/windows/process_creation/proc_creation_win_certoc_download.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [File Download From IP Based URL Via CertOC.EXE](rules/windows/process_creation/proc_creation_win_certoc_download_direct_ip.kql) | high | command-and-control, execution, T1105 | DeviceProcessEvents |
| [DLL Loaded via CertOC.EXE](rules/windows/process_creation/proc_creation_win_certoc_load_dll.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious DLL Loaded via CertOC.EXE](rules/windows/process_creation/proc_creation_win_certoc_load_dll_susp_locations.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [New Root Certificate Installed Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_certificate_installation.kql) | medium | defense-impairment, T1553.004 | DeviceProcessEvents |
| [File Decoded From Base64/Hex Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_decode.kql) | high | stealth, T1027 | DeviceProcessEvents |
| [Suspicious Download Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_download.kql) | medium | stealth, T1027, command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious File Downloaded From Direct IP Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.kql) | high | stealth, T1027, command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.kql) | high | stealth, T1027, command-and-control, T1105 | DeviceProcessEvents |
| [File Encoded To Base64 Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_encode.kql) | medium | stealth, T1027 | DeviceProcessEvents |
| [Suspicious File Encoded To Base64 Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_encode_susp_extensions.kql) | high | stealth, T1027 | DeviceProcessEvents |
| [File In Suspicious Location Encoded To Base64 Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_encode_susp_location.kql) | high | stealth, T1027 | DeviceProcessEvents |
| [Certificate Exported Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_export_pfx.kql) | medium | stealth, T1027 | DeviceProcessEvents |
| [Potential NTLM Coercion Via Certutil.EXE](rules/windows/process_creation/proc_creation_win_certutil_ntlm_coercion.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Console CodePage Lookup Via CHCP](rules/windows/process_creation/proc_creation_win_chcp_codepage_lookup.kql) | medium | discovery, T1614.001 | DeviceProcessEvents |
| [Suspicious CodePage Switch Via CHCP](rules/windows/process_creation/proc_creation_win_chcp_codepage_switch.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [Deleted Data Overwritten Via Cipher.EXE](rules/windows/process_creation/proc_creation_win_cipher_overwrite_deleted_data.kql) | medium | impact, T1485 | DeviceProcessEvents |
| [Process Access via TrolleyExpress Exclusion](rules/windows/process_creation/proc_creation_win_citrix_trolleyexpress_procdump.kql) | high | stealth, T1218.011, credential-access, T1003.001 | DeviceProcessEvents |
| [Cloudflared Portable Execution](rules/windows/process_creation/proc_creation_win_cloudflared_portable_execution.kql) | medium | command-and-control, T1090.001 | DeviceProcessEvents |
| [Cloudflared Quick Tunnel Execution](rules/windows/process_creation/proc_creation_win_cloudflared_quicktunnel_execution.kql) | medium | command-and-control, T1090.001 | DeviceProcessEvents |
| [Cloudflared Tunnel Connections Cleanup](rules/windows/process_creation/proc_creation_win_cloudflared_tunnel_cleanup.kql) | medium | command-and-control, T1102, T1090, T1572 | DeviceProcessEvents |
| [Cloudflared Tunnel Execution](rules/windows/process_creation/proc_creation_win_cloudflared_tunnel_run.kql) | medium | command-and-control, T1102, T1090, T1572 | DeviceProcessEvents |
| [Change Default File Association To Executable Via Assoc](rules/windows/process_creation/proc_creation_win_cmd_assoc_tamper_exe_file_association.kql) | high | privilege-escalation, persistence, T1546.001 | DeviceProcessEvents |
| [Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE](rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.kql) | high | credential-access | DeviceProcessEvents |
| [Curl Download And Execute Combination](rules/windows/process_creation/proc_creation_win_cmd_curl_download_exec_combo.kql) | high | stealth, T1218, command-and-control, T1105 | DeviceProcessEvents |
| [Greedy File Deletion Using Del](rules/windows/process_creation/proc_creation_win_cmd_del_greedy_deletion.kql) | medium | stealth, T1070.004 | DeviceProcessEvents |
| [Potential Dosfuscation Activity](rules/windows/process_creation/proc_creation_win_cmd_dosfuscation.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Command Line Execution with Suspicious URL and AppData Strings](rules/windows/process_creation/proc_creation_win_cmd_http_appdata.kql) | medium | execution, command-and-control, T1059.003, T1059.001, T1105 | DeviceProcessEvents |
| [Potential Privilege Escalation Using Symlink Between Osk and Cmd](rules/windows/process_creation/proc_creation_win_cmd_mklink_osk_cmd.kql) | high | privilege-escalation, persistence, T1546.008 | DeviceProcessEvents |
| [VolumeShadowCopy Symlink Creation Via Mklink](rules/windows/process_creation/proc_creation_win_cmd_mklink_shadow_copies_access_symlink.kql) | high | credential-access, T1003.002, T1003.003 | DeviceProcessEvents |
| [Suspicious File Execution From Internet Hosted WebDav Share](rules/windows/process_creation/proc_creation_win_cmd_net_use_and_exec_combo.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Cmd.EXE Missing Space Characters Execution Anomaly](rules/windows/process_creation/proc_creation_win_cmd_no_space_execution.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [NtdllPipe Like Activity Execution](rules/windows/process_creation/proc_creation_win_cmd_ntdllpipe_redirect.kql) | high | defense-impairment | DeviceProcessEvents |
| [Potential CommandLine Path Traversal Via Cmd.EXE](rules/windows/process_creation/proc_creation_win_cmd_path_traversal.kql) | high | execution, T1059.003 | DeviceProcessEvents |
| [Potentially Suspicious Ping/Copy Command Combination](rules/windows/process_creation/proc_creation_win_cmd_ping_copy_combined_execution.kql) | medium | stealth, T1070.004 | DeviceProcessEvents |
| [Suspicious Ping/Del Command Combination](rules/windows/process_creation/proc_creation_win_cmd_ping_del_combined_execution.kql) | high | stealth, T1070.004 | DeviceProcessEvents |
| [Potentially Suspicious CMD Shell Output Redirect](rules/windows/process_creation/proc_creation_win_cmd_redirection_susp_folder.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Copy From VolumeShadowCopy Via Cmd.EXE](rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.kql) | high | impact, T1490 | DeviceProcessEvents |
| [Read Contents From Stdin Via Cmd.EXE](rules/windows/process_creation/proc_creation_win_cmd_stdin_redirect.kql) | medium | execution, T1059.003 | DeviceProcessEvents |
| [Sticky Key Like Backdoor Execution](rules/windows/process_creation/proc_creation_win_cmd_sticky_key_like_backdoor_execution.kql) | critical | privilege-escalation, persistence, T1546.008 | DeviceProcessEvents |
| [Persistence Via Sticky Key Backdoor](rules/windows/process_creation/proc_creation_win_cmd_sticky_keys_replace.kql) | critical | persistence, T1546.008, privilege-escalation | DeviceProcessEvents |
| [Potential Download/Upload Activity Using Type Command](rules/windows/process_creation/proc_creation_win_cmd_type_arbitrary_file_download.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Unusual Parent Process For Cmd.EXE](rules/windows/process_creation/proc_creation_win_cmd_unusual_parent.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [New Generic Credentials Added Via Cmdkey.EXE](rules/windows/process_creation/proc_creation_win_cmdkey_adding_generic_creds.kql) | medium | credential-access, T1003.005 | DeviceProcessEvents |
| [Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE](rules/windows/process_creation/proc_creation_win_cmdkey_recon.kql) | high | credential-access, T1003.005 | DeviceProcessEvents |
| [Potential Arbitrary File Download Via Cmdl32.EXE](rules/windows/process_creation/proc_creation_win_cmdl32_arbitrary_file_download.kql) | medium | execution, stealth, T1218, T1202 | DeviceProcessEvents |
| [CMSTP Execution Process Creation](rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.kql) | high | execution, stealth, T1218.003, G0069 | DeviceProcessEvents |
| [Arbitrary File Download Via ConfigSecurityPolicy.EXE](rules/windows/process_creation/proc_creation_win_configsecuritypolicy_download_file.kql) | medium | exfiltration, T1567 | DeviceProcessEvents |
| [Powershell Executed From Headless ConHost Process](rules/windows/process_creation/proc_creation_win_conhost_headless_powershell.kql) | medium | execution, stealth, T1059.001, T1059.003, T1564.003 | DeviceProcessEvents |
| [Conhost.exe CommandLine Path Traversal](rules/windows/process_creation/proc_creation_win_conhost_path_traversal.kql) | high | execution, T1059.003 | DeviceProcessEvents |
| [Conhost Spawned By Uncommon Parent Process](rules/windows/process_creation/proc_creation_win_conhost_uncommon_parent.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Control Panel Items](rules/windows/process_creation/proc_creation_win_control_panel_item.kql) | high | privilege-escalation, execution, stealth, T1218.002, persistence, T1546 | DeviceProcessEvents |
| [CreateDump Process Dump](rules/windows/process_creation/proc_creation_win_createdump_lolbin_execution.kql) | high | stealth, T1036, T1003.001, credential-access | DeviceProcessEvents |
| [Dynamic .NET Compilation Via Csc.EXE](rules/windows/process_creation/proc_creation_win_csc_susp_dynamic_compilation.kql) | medium | stealth, T1027.004 | DeviceProcessEvents |
| [Csc.EXE Execution Form Potentially Suspicious Parent](rules/windows/process_creation/proc_creation_win_csc_susp_parent.kql) | high | execution, stealth, T1059.005, T1059.007, T1218.005, T1027.004 | DeviceProcessEvents |
| [Suspicious Csi.exe Usage](rules/windows/process_creation/proc_creation_win_csi_execution.kql) | medium | lateral-movement, execution, stealth, T1072, T1218 | DeviceProcessEvents |
| [Suspicious Use of CSharp Interactive Console](rules/windows/process_creation/proc_creation_win_csi_use_of_csharp_console.kql) | high | execution, stealth, T1127 | DeviceProcessEvents |
| [Active Directory Structure Export Via Csvde.EXE](rules/windows/process_creation/proc_creation_win_csvde_export.kql) | medium | exfiltration, discovery, T1087.002 | DeviceProcessEvents |
| [Potential Cookies Session Hijacking](rules/windows/process_creation/proc_creation_win_curl_cookie_hijacking.kql) | medium | execution | DeviceProcessEvents |
| [Curl Web Request With Potential Custom User-Agent](rules/windows/process_creation/proc_creation_win_curl_custom_user_agent.kql) | medium | execution | DeviceProcessEvents |
| [File Download From IP URL Via Curl.EXE](rules/windows/process_creation/proc_creation_win_curl_download_direct_ip_exec.kql) | medium | execution | DeviceProcessEvents |
| [Suspicious File Download From IP Via Curl.EXE](rules/windows/process_creation/proc_creation_win_curl_download_direct_ip_susp_extensions.kql) | high | execution | DeviceProcessEvents |
| [Suspicious File Download From File Sharing Domain Via Curl.EXE](rules/windows/process_creation/proc_creation_win_curl_download_susp_file_sharing_domains.kql) | high | execution | DeviceProcessEvents |
| [Insecure Transfer Via Curl.EXE](rules/windows/process_creation/proc_creation_win_curl_insecure_connection.kql) | medium | execution | DeviceProcessEvents |
| [Insecure Proxy/DOH Transfer Via Curl.EXE](rules/windows/process_creation/proc_creation_win_curl_insecure_proxy_or_doh.kql) | medium | execution | DeviceProcessEvents |
| [Local File Read Using Curl.EXE](rules/windows/process_creation/proc_creation_win_curl_local_file_read.kql) | medium | execution | DeviceProcessEvents |
| [NTLM Hash Leak Via Curl NTLM Authentication](rules/windows/process_creation/proc_creation_win_curl_ntlm_hash_leak_attempt.kql) | high | credential-access, T1187 | DeviceProcessEvents |
| [Suspicious Curl.EXE Download](rules/windows/process_creation/proc_creation_win_curl_susp_download.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious CustomShellHost Execution](rules/windows/process_creation/proc_creation_win_customshellhost_susp_exec.kql) | high | stealth, T1216 | DeviceProcessEvents |
| [Uncommon Child Process Of Defaultpack.EXE](rules/windows/process_creation/proc_creation_win_defaultpack_uncommon_child_process.kql) | medium | stealth, T1218, execution | DeviceProcessEvents |
| [Remote File Download Via Desktopimgdownldr Utility](rules/windows/process_creation/proc_creation_win_desktopimgdownldr_remote_file_download.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Desktopimgdownldr Command](rules/windows/process_creation/proc_creation_win_desktopimgdownldr_susp_execution.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [DeviceCredentialDeployment Execution](rules/windows/process_creation/proc_creation_win_device_credential_deployment.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential DLL Sideloading Via DeviceEnroller.EXE](rules/windows/process_creation/proc_creation_win_deviceenroller_dll_sideloading.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Arbitrary MSI Download Via Devinit.EXE](rules/windows/process_creation/proc_creation_win_devinit_lolbin_usage.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Potentially Suspicious Child Process Of ClickOnce Application](rules/windows/process_creation/proc_creation_win_dfsvc_suspicious_child_processes.kql) | medium | execution, stealth | DeviceProcessEvents |
| [Potentially Suspicious Child Process Of DiskShadow.EXE](rules/windows/process_creation/proc_creation_win_diskshadow_child_process_susp.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Diskshadow Script Mode - Uncommon Script Extension Execution](rules/windows/process_creation/proc_creation_win_diskshadow_script_mode_susp_ext.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Diskshadow Script Mode - Execution From Potential Suspicious Location](rules/windows/process_creation/proc_creation_win_diskshadow_script_mode_susp_location.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [PowerShell Web Access Feature Enabled Via DISM](rules/windows/process_creation/proc_creation_win_dism_enable_powershell_web_access_feature.kql) | high | privilege-escalation, persistence, T1548.002 | DeviceProcessEvents |
| [Dism Remove Online Package](rules/windows/process_creation/proc_creation_win_dism_remove.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [DLL Sideloading by VMware Xfer Utility](rules/windows/process_creation/proc_creation_win_dll_sideload_vmware_xfer.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Dllhost.EXE Execution Anomaly](rules/windows/process_creation/proc_creation_win_dllhost_no_cli_execution.kql) | high | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [DNS Exfiltration and Tunneling Tools Execution](rules/windows/process_creation/proc_creation_win_dns_exfiltration_tools_execution.kql) | high | exfiltration, T1048.001, command-and-control, T1071.004, T1132.001 | DeviceProcessEvents |
| [Unusual Child Process of dns.exe](rules/windows/process_creation/proc_creation_win_dns_susp_child_process.kql) | high | persistence, initial-access, T1133 | DeviceProcessEvents |
| [Potential Discovery Activity Via Dnscmd.EXE](rules/windows/process_creation/proc_creation_win_dnscmd_discovery.kql) | medium | discovery, execution | DeviceProcessEvents |
| [New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE](rules/windows/process_creation/proc_creation_win_dnscmd_install_new_server_level_plugin_dll.kql) | high | privilege-escalation, persistence, execution, stealth, defense-impairment, T1574.001, T1112 | DeviceProcessEvents |
| [Potential Application Whitelisting Bypass via Dnx.EXE](rules/windows/process_creation/proc_creation_win_dnx_execute_csharp_code.kql) | medium | stealth, T1218, T1027.004 | DeviceProcessEvents |
| [Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE](rules/windows/process_creation/proc_creation_win_dotnet_arbitrary_dll_csproj_execution.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Binary Proxy Execution Via Dotnet-Trace.EXE](rules/windows/process_creation/proc_creation_win_dotnet_trace_lolbin_execution.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Process Memory Dump Via Dotnet-Dump](rules/windows/process_creation/proc_creation_win_dotnetdump_memory_dump.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential Recon Activity Using DriverQuery.EXE](rules/windows/process_creation/proc_creation_win_driverquery_recon.kql) | high | discovery | DeviceProcessEvents |
| [DriverQuery.EXE Execution](rules/windows/process_creation/proc_creation_win_driverquery_usage.kql) | medium | discovery | DeviceProcessEvents |
| [Potentially Over Permissive Permissions Granted Using Dsacls.EXE](rules/windows/process_creation/proc_creation_win_dsacls_abuse_permissions.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential Password Spraying Attempt Using Dsacls.EXE](rules/windows/process_creation/proc_creation_win_dsacls_password_spray.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Domain Trust Discovery Via Dsquery](rules/windows/process_creation/proc_creation_win_dsquery_domain_trust_discovery.kql) | medium | discovery, T1482 | DeviceProcessEvents |
| [Suspicious Kernel Dump Using Dtrace](rules/windows/process_creation/proc_creation_win_dtrace_kernel_dump.kql) | high | discovery, T1082 | DeviceProcessEvents |
| [Potential Windows Defender AV Bypass Via Dump64.EXE Rename](rules/windows/process_creation/proc_creation_win_dump64_defender_av_bypass_rename.kql) | high | credential-access, T1003.001 | DeviceProcessEvents |
| [DumpMinitool Execution](rules/windows/process_creation/proc_creation_win_dumpminitool_execution.kql) | medium | stealth, T1036, T1003.001, credential-access | DeviceProcessEvents |
| [Suspicious DumpMinitool Execution](rules/windows/process_creation/proc_creation_win_dumpminitool_susp_execution.kql) | high | credential-access, stealth, T1036, T1003.001 | DeviceProcessEvents |
| [New Capture Session Launched Via DXCap.EXE](rules/windows/process_creation/proc_creation_win_dxcap_arbitrary_binary_execution.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Esentutl Gather Credentials](rules/windows/process_creation/proc_creation_win_esentutl_params.kql) | medium | credential-access, T1003, T1003.003, S0404 | DeviceProcessEvents |
| [Copying Sensitive Files with Credential Data](rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.kql) | high | credential-access, T1003.002, T1003.003, S0404 | DeviceProcessEvents |
| [Esentutl Steals Browser Information](rules/windows/process_creation/proc_creation_win_esentutl_webcache.kql) | medium | collection, T1005 | DeviceProcessEvents |
| [Potentially Suspicious Event Viewer Child Process](rules/windows/process_creation/proc_creation_win_eventvwr_susp_child_process.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Potentially Suspicious Cabinet File Expansion](rules/windows/process_creation/proc_creation_win_expand_cabinet_files.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Explorer Process Tree Break](rules/windows/process_creation/proc_creation_win_explorer_break_process_tree.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell](rules/windows/process_creation/proc_creation_win_explorer_folder_shortcut_via_shell_binary.kql) | high | discovery, T1135 | DeviceProcessEvents |
| [Explorer NOUACCHECK Flag](rules/windows/process_creation/proc_creation_win_explorer_nouaccheck.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Remote File Download Via Findstr.EXE](rules/windows/process_creation/proc_creation_win_findstr_download.kql) | medium | credential-access, command-and-control, stealth, T1218, T1564.004, T1552.001, T1105 | DeviceProcessEvents |
| [Findstr GPP Passwords](rules/windows/process_creation/proc_creation_win_findstr_gpp_passwords.kql) | high | credential-access, T1552.006 | DeviceProcessEvents |
| [Findstr Launching .lnk File](rules/windows/process_creation/proc_creation_win_findstr_lnk.kql) | medium | stealth, T1036, T1202, T1027.003 | DeviceProcessEvents |
| [LSASS Process Reconnaissance Via Findstr.EXE](rules/windows/process_creation/proc_creation_win_findstr_lsass.kql) | high | credential-access, T1552.006 | DeviceProcessEvents |
| [Permission Misconfiguration Reconnaissance Via Findstr.EXE](rules/windows/process_creation/proc_creation_win_findstr_recon_everyone.kql) | medium | credential-access, T1552.006 | DeviceProcessEvents |
| [Recon Command Output Piped To Findstr.EXE](rules/windows/process_creation/proc_creation_win_findstr_recon_pipe_output.kql) | medium | discovery, T1057 | DeviceProcessEvents |
| [Security Tools Keyword Lookup Via Findstr.EXE](rules/windows/process_creation/proc_creation_win_findstr_security_keyword_lookup.kql) | medium | discovery, T1518.001 | DeviceProcessEvents |
| [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](rules/windows/process_creation/proc_creation_win_findstr_sysmon_discovery_via_default_altitude.kql) | high | discovery, T1518.001 | DeviceProcessEvents |
| [Finger.EXE Execution](rules/windows/process_creation/proc_creation_win_finger_execution.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [Filter Driver Unloaded Via Fltmc.EXE](rules/windows/process_creation/proc_creation_win_fltmc_unload_driver.kql) | medium | stealth, defense-impairment, T1070, T1685, T1685.001 | DeviceProcessEvents |
| [Sysmon Driver Unloaded Via Fltmc.EXE](rules/windows/process_creation/proc_creation_win_fltmc_unload_driver_sysmon.kql) | high | stealth, defense-impairment, T1070, T1685, T1685.001 | DeviceProcessEvents |
| [Forfiles.EXE Child Process Masquerading](rules/windows/process_creation/proc_creation_win_forfiles_child_process_masquerading.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Forfiles Command Execution](rules/windows/process_creation/proc_creation_win_forfiles_proxy_execution_.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Uncommon FileSystem Load Attempt By Format.com](rules/windows/process_creation/proc_creation_win_format_uncommon_filesystem_load.kql) | high | stealth | DeviceProcessEvents |
| [Use of FSharp Interpreters](rules/windows/process_creation/proc_creation_win_fsi_fsharp_code_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Potentially Suspicious NTFS Symlink Behavior Modification](rules/windows/process_creation/proc_creation_win_fsutil_symlinkevaluation.kql) | medium | execution, defense-impairment, T1059, T1222.001 | DeviceProcessEvents |
| [Fsutil Suspicious Invocation](rules/windows/process_creation/proc_creation_win_fsutil_usage.kql) | high | impact, stealth, T1070, T1485 | DeviceProcessEvents |
| [Potential Arbitrary Command Execution Via FTP.EXE](rules/windows/process_creation/proc_creation_win_ftp_arbitrary_command_execution.kql) | medium | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Arbitrary File Download Via GfxDownloadWrapper.EXE](rules/windows/process_creation/proc_creation_win_gfxdownloadwrapper_arbitrary_file_download.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Git Clone](rules/windows/process_creation/proc_creation_win_git_susp_clone.kql) | medium | reconnaissance, T1593.003 | DeviceProcessEvents |
| [Github Self-Hosted Runner Execution](rules/windows/process_creation/proc_creation_win_github_self_hosted_runner.kql) | medium | command-and-control, T1102.002, T1071 | DeviceProcessEvents |
| [Potentially Suspicious GoogleUpdate Child Process](rules/windows/process_creation/proc_creation_win_googleupdate_susp_child_process.kql) | high | stealth | DeviceProcessEvents |
| [File Decryption Using Gpg4win](rules/windows/process_creation/proc_creation_win_gpg4win_decryption.kql) | medium | execution | DeviceProcessEvents |
| [File Encryption Using Gpg4win](rules/windows/process_creation/proc_creation_win_gpg4win_encryption.kql) | medium | execution | DeviceProcessEvents |
| [Portable Gpg.EXE Execution](rules/windows/process_creation/proc_creation_win_gpg4win_portable_execution.kql) | medium | impact, T1486 | DeviceProcessEvents |
| [File Encryption/Decryption Via Gpg4win From Suspicious Locations](rules/windows/process_creation/proc_creation_win_gpg4win_susp_location.kql) | high | execution | DeviceProcessEvents |
| [Gpresult Display Group Policy Information](rules/windows/process_creation/proc_creation_win_gpresult_execution.kql) | medium | discovery, T1615 | DeviceProcessEvents |
| [Arbitrary Binary Execution Using GUP Utility](rules/windows/process_creation/proc_creation_win_gup_arbitrary_binary_execution.kql) | medium | execution | DeviceProcessEvents |
| [File Download Using Notepad++ GUP Utility](rules/windows/process_creation/proc_creation_win_gup_download.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious GUP Usage](rules/windows/process_creation/proc_creation_win_gup_suspicious_execution.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Remote CHM File Download/Execution Via HH.EXE](rules/windows/process_creation/proc_creation_win_hh_chm_remote_download_or_execution.kql) | high | stealth, T1218.001 | DeviceProcessEvents |
| [HTML Help HH.EXE Suspicious Child Process](rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.kql) | high | execution, initial-access, stealth, T1047, T1059.001, T1059.003, T1059.005, T1059.007, T1218, T1218.001, T1218.010, T1218.011, T1566, T1566.001 | DeviceProcessEvents |
| [Suspicious HH.EXE Execution](rules/windows/process_creation/proc_creation_win_hh_susp_execution.kql) | high | execution, initial-access, stealth, T1047, T1059.001, T1059.003, T1059.005, T1059.007, T1218, T1218.001, T1218.010, T1218.011, T1566, T1566.001 | DeviceProcessEvents |
| [HackTool - ADCSPwn Execution](rules/windows/process_creation/proc_creation_win_hktl_adcspwn.kql) | high | collection, credential-access, T1557.001 | DeviceProcessEvents |
| [HackTool - Bloodhound/Sharphound Execution](rules/windows/process_creation/proc_creation_win_hktl_bloodhound_sharphound.kql) | high | discovery, T1087.001, T1087.002, T1482, T1069.001, T1069.002, execution, T1059.001 | DeviceProcessEvents |
| [HackTool - F-Secure C3 Load by Rundll32](rules/windows/process_creation/proc_creation_win_hktl_c3_rundll32_pattern.kql) | critical | stealth, T1218.011 | DeviceProcessEvents |
| [HackTool - Certify Execution](rules/windows/process_creation/proc_creation_win_hktl_certify.kql) | high | discovery, credential-access, T1649 | DeviceProcessEvents |
| [HackTool - Certipy Execution](rules/windows/process_creation/proc_creation_win_hktl_certipy.kql) | high | discovery, credential-access, T1649 | DeviceProcessEvents |
| [Operator Bloopers Cobalt Strike Commands](rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_bloopers_cmd.kql) | high | execution, T1059.003 | DeviceProcessEvents |
| [Operator Bloopers Cobalt Strike Modules](rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_bloopers_modules.kql) | high | execution, T1059.003 | DeviceProcessEvents |
| [CobaltStrike Load by Rundll32](rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_load_by_rundll32.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Potential CobaltStrike Process Patterns](rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_process_patterns.kql) | high | execution, T1059 | DeviceProcessEvents |
| [HackTool - Covenant PowerShell Launcher](rules/windows/process_creation/proc_creation_win_hktl_covenant.kql) | high | execution, stealth, T1059.001, T1564.003 | DeviceProcessEvents |
| [HackTool - CrackMapExec Execution](rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution.kql) | high | execution, persistence, privilege-escalation, credential-access, discovery, T1047, T1053, T1059.003, T1059.001, T1110, T1201 | DeviceProcessEvents |
| [HackTool - CrackMapExec Execution Patterns](rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution_patterns.kql) | high | privilege-escalation, persistence, execution, T1047, T1053, T1059.003, T1059.001, S0106 | DeviceProcessEvents |
| [HackTool - CrackMapExec Process Patterns](rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_patterns.kql) | high | credential-access, T1003.001 | DeviceProcessEvents |
| [HackTool - CrackMapExec PowerShell Obfuscation](rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_powershell_obfuscation.kql) | high | execution, stealth, T1059.001, T1027.005 | DeviceProcessEvents |
| [HackTool - DInjector PowerShell Cradle Execution](rules/windows/process_creation/proc_creation_win_hktl_dinjector.kql) | critical | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [HackTool - EDRSilencer Execution](rules/windows/process_creation/proc_creation_win_hktl_edrsilencer.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [HackTool - Empire PowerShell Launch Parameters](rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_launch.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [HackTool - Empire PowerShell UAC Bypass](rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_uac_bypass.kql) | critical | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [HackTool - WinRM Access Via Evil-WinRM](rules/windows/process_creation/proc_creation_win_hktl_evil_winrm.kql) | medium | lateral-movement, T1021.006 | DeviceProcessEvents |
| [Hacktool Execution - PE Metadata](rules/windows/process_creation/proc_creation_win_hktl_execution_via_pe_metadata.kql) | high | credential-access, resource-development, T1588.002, T1003 | DeviceProcessEvents |
| [HackTool - GMER Rootkit Detector and Remover Execution](rules/windows/process_creation/proc_creation_win_hktl_gmer.kql) | high | stealth | DeviceProcessEvents |
| [HackTool - Hashcat Password Cracker Execution](rules/windows/process_creation/proc_creation_win_hktl_hashcat.kql) | high | credential-access, T1110.002 | DeviceProcessEvents |
| [HackTool - Htran/NATBypass Execution](rules/windows/process_creation/proc_creation_win_hktl_htran_or_natbypass.kql) | high | command-and-control, T1090, S0040 | DeviceProcessEvents |
| [HackTool - Hydra Password Bruteforce Execution](rules/windows/process_creation/proc_creation_win_hktl_hydra.kql) | high | credential-access, T1110, T1110.001 | DeviceProcessEvents |
| [HackTool - Potential Impacket Lateral Movement Activity](rules/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.kql) | high | execution, T1047, lateral-movement, T1021.003 | DeviceProcessEvents |
| [HackTool - Impacket Tools Execution](rules/windows/process_creation/proc_creation_win_hktl_impacket_tools.kql) | high | collection, execution, credential-access, T1557.001 | DeviceProcessEvents |
| [HackTool - Impersonate Execution](rules/windows/process_creation/proc_creation_win_hktl_impersonate.kql) | medium | privilege-escalation, stealth, T1134.001, T1134.003 | DeviceProcessEvents |
| [HackTool - Inveigh Execution](rules/windows/process_creation/proc_creation_win_hktl_inveigh.kql) | critical | credential-access, T1003.001 | DeviceProcessEvents |
| [Invoke-Obfuscation CLIP+ Launcher](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_clip.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation Obfuscated IEX Invocation](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_obfuscated_iex_commandline.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation STDIN+ Launcher](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_stdin.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation VAR+ Launcher](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_var.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation COMPRESS OBFUSCATION](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_compress.kql) | medium | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation Via Stdin](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_stdin.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation Via Use Clip](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_clip.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation Via Use MSHTA](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_mhsta.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION](rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_var.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [HackTool - Jlaive In-Memory Assembly Execution](rules/windows/process_creation/proc_creation_win_hktl_jlaive_batch_execution.kql) | medium | execution, T1059.003 | DeviceProcessEvents |
| [HackTool - Koadic Execution](rules/windows/process_creation/proc_creation_win_hktl_koadic.kql) | high | execution, T1059.003, T1059.005, T1059.007 | DeviceProcessEvents |
| [HackTool - KrbRelay Execution](rules/windows/process_creation/proc_creation_win_hktl_krbrelay.kql) | high | credential-access, T1558.003 | DeviceProcessEvents |
| [HackTool - RemoteKrbRelay Execution](rules/windows/process_creation/proc_creation_win_hktl_krbrelay_remote.kql) | high | credential-access, T1558.003 | DeviceProcessEvents |
| [HackTool - KrbRelayUp Execution](rules/windows/process_creation/proc_creation_win_hktl_krbrelayup.kql) | high | credential-access, T1558.003, lateral-movement, T1550.003 | DeviceProcessEvents |
| [Potential Meterpreter/CobaltStrike Activity](rules/windows/process_creation/proc_creation_win_hktl_meterpreter_getsystem.kql) | high | privilege-escalation, stealth, T1134.001, T1134.002 | DeviceProcessEvents |
| [HackTool - Mimikatz Execution](rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.kql) | high | credential-access, T1003.001, T1003.002, T1003.004, T1003.005, T1003.006 | DeviceProcessEvents |
| [HackTool - PCHunter Execution](rules/windows/process_creation/proc_creation_win_hktl_pchunter.kql) | high | execution, discovery, T1082, T1057, T1012, T1083, T1007 | DeviceProcessEvents |
| [HackTool - Default PowerSploit/Empire Scheduled Task Creation](rules/windows/process_creation/proc_creation_win_hktl_powersploit_empire_default_schtasks.kql) | high | execution, persistence, privilege-escalation, S0111, G0022, G0060, T1053.005, T1059.001 | DeviceProcessEvents |
| [HackTool - PowerTool Execution](rules/windows/process_creation/proc_creation_win_hktl_powertool.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [HackTool - PurpleSharp Execution](rules/windows/process_creation/proc_creation_win_hktl_purplesharp_indicators.kql) | critical | T1587, resource-development | DeviceProcessEvents |
| [HackTool - Pypykatz Credentials Dumping Activity](rules/windows/process_creation/proc_creation_win_hktl_pypykatz.kql) | high | credential-access, T1003.002 | DeviceProcessEvents |
| [HackTool - Quarks PwDump Execution](rules/windows/process_creation/proc_creation_win_hktl_quarks_pwdump.kql) | high | credential-access, T1003.002 | DeviceProcessEvents |
| [HackTool - RedMimicry Winnti Playbook Execution](rules/windows/process_creation/proc_creation_win_hktl_redmimicry_winnti_playbook.kql) | high | execution, stealth, T1106, T1059.003, T1218.011 | DeviceProcessEvents |
| [Potential SMB Relay Attack Tool Execution](rules/windows/process_creation/proc_creation_win_hktl_relay_attacks_tools.kql) | critical | collection, execution, credential-access, T1557.001 | DeviceProcessEvents |
| [HackTool - Rubeus Execution](rules/windows/process_creation/proc_creation_win_hktl_rubeus.kql) | critical | credential-access, T1003, T1558.003, lateral-movement, T1550.003 | DeviceProcessEvents |
| [HackTool - SafetyKatz Execution](rules/windows/process_creation/proc_creation_win_hktl_safetykatz.kql) | critical | credential-access, T1003.001 | DeviceProcessEvents |
| [HackTool - SecurityXploded Execution](rules/windows/process_creation/proc_creation_win_hktl_secutyxploded.kql) | critical | credential-access, T1555 | DeviceProcessEvents |
| [HackTool - SharpChisel Execution](rules/windows/process_creation/proc_creation_win_hktl_sharp_chisel.kql) | high | command-and-control, T1090.001 | DeviceProcessEvents |
| [HackTool - SharpDPAPI Execution](rules/windows/process_creation/proc_creation_win_hktl_sharp_dpapi_execution.kql) | high | privilege-escalation, stealth, T1134.001, T1134.003 | DeviceProcessEvents |
| [HackTool - SharpImpersonation Execution](rules/windows/process_creation/proc_creation_win_hktl_sharp_impersonation.kql) | high | privilege-escalation, stealth, T1134.001, T1134.003 | DeviceProcessEvents |
| [HackTool - SharpLDAPmonitor Execution](rules/windows/process_creation/proc_creation_win_hktl_sharp_ldap_monitor.kql) | medium | discovery | DeviceProcessEvents |
| [HackTool - SharPersist Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpersist.kql) | high | privilege-escalation, execution, persistence, T1053 | DeviceProcessEvents |
| [HackTool - SharpEvtMute Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpevtmute.kql) | high | defense-impairment, T1685.001 | DeviceProcessEvents |
| [HackTool - SharpLdapWhoami Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpldapwhoami.kql) | high | discovery, T1033 | DeviceProcessEvents |
| [HackTool - SharpMove Tool Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpmove.kql) | high | lateral-movement, T1021.002 | DeviceProcessEvents |
| [HackTool - SharpUp PrivEsc Tool Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpup.kql) | critical | persistence, privilege-escalation, discovery, execution, stealth, T1615, T1569.002, T1574.005 | DeviceProcessEvents |
| [HackTool - SharpView Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpview.kql) | high | discovery, T1049, T1069.002, T1482, T1135, T1033 | DeviceProcessEvents |
| [HackTool - SharpWSUS/WSUSpendu Execution](rules/windows/process_creation/proc_creation_win_hktl_sharpwsus_wsuspendu_execution.kql) | high | execution, lateral-movement, T1210 | DeviceProcessEvents |
| [HackTool - SILENTTRINITY Stager Execution](rules/windows/process_creation/proc_creation_win_hktl_silenttrinity_stager.kql) | high | command-and-control, T1071 | DeviceProcessEvents |
| [HackTool - Sliver C2 Implant Activity Pattern](rules/windows/process_creation/proc_creation_win_hktl_sliver_c2_execution_pattern.kql) | critical | execution, T1059 | DeviceProcessEvents |
| [HackTool - SOAPHound Execution](rules/windows/process_creation/proc_creation_win_hktl_soaphound_execution.kql) | high | discovery, T1087 | DeviceProcessEvents |
| [HackTool - Stracciatella Execution](rules/windows/process_creation/proc_creation_win_hktl_stracciatella_execution.kql) | high | execution, defense-impairment, T1059, T1685 | DeviceProcessEvents |
| [HackTool - TruffleSnout Execution](rules/windows/process_creation/proc_creation_win_hktl_trufflesnout.kql) | high | discovery, T1482 | DeviceProcessEvents |
| [HackTool - winPEAS Execution](rules/windows/process_creation/proc_creation_win_hktl_winpeas.kql) | high | privilege-escalation, discovery, T1082, T1087, T1046 | DeviceProcessEvents |
| [HackTool - WinPwn Execution](rules/windows/process_creation/proc_creation_win_hktl_winpwn.kql) | high | credential-access, discovery, execution, privilege-escalation, T1046, T1082, T1106, T1518, T1548.002, T1552.001, T1555, T1555.003 | DeviceProcessEvents |
| [HackTool - Wmiexec Default Powershell Command](rules/windows/process_creation/proc_creation_win_hktl_wmiexec_default_powershell.kql) | high | lateral-movement, stealth | DeviceProcessEvents |
| [HackTool - XORDump Execution](rules/windows/process_creation/proc_creation_win_hktl_xordump.kql) | high | stealth, T1036, T1003.001, credential-access | DeviceProcessEvents |
| [Suspicious ZipExec Execution](rules/windows/process_creation/proc_creation_win_hktl_zipexec.kql) | medium | execution, stealth, T1218, T1202 | DeviceProcessEvents |
| [Suspicious HWP Sub Processes](rules/windows/process_creation/proc_creation_win_hwp_exploits.kql) | high | initial-access, T1566.001, execution, T1203, T1059.003, G0032 | DeviceProcessEvents |
| [Potential Fake Instance Of Hxtsr.EXE Executed](rules/windows/process_creation/proc_creation_win_hxtsr_masquerading.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [Use Icacls to Hide File to Everyone](rules/windows/process_creation/proc_creation_win_icacls_deny.kql) | medium | stealth, T1564.001 | DeviceProcessEvents |
| [File Download And Execution Via IEExec.EXE](rules/windows/process_creation/proc_creation_win_ieexec_download.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location](rules/windows/process_creation/proc_creation_win_iexpress_susp_execution.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Disable Windows IIS HTTP Logging](rules/windows/process_creation/proc_creation_win_iis_appcmd_http_logging.kql) | high | defense-impairment, T1685.001 | DeviceProcessEvents |
| [Microsoft IIS Service Account Password Dumped](rules/windows/process_creation/proc_creation_win_iis_appcmd_service_account_password_dumped.kql) | high | credential-access, T1003 | DeviceProcessEvents |
| [IIS Native-Code Module Command Line Installation](rules/windows/process_creation/proc_creation_win_iis_appcmd_susp_module_install.kql) | medium | persistence, T1505.003 | DeviceProcessEvents |
| [Suspicious IIS URL GlobalRules Rewrite Via AppCmd](rules/windows/process_creation/proc_creation_win_iis_appcmd_susp_rewrite_rule.kql) | medium | stealth | DeviceProcessEvents |
| [Microsoft IIS Connection Strings Decryption](rules/windows/process_creation/proc_creation_win_iis_connection_strings_decryption.kql) | high | credential-access, T1003 | DeviceProcessEvents |
| [Suspicious IIS Module Registration](rules/windows/process_creation/proc_creation_win_iis_susp_module_registration.kql) | high | persistence, T1505.004 | DeviceProcessEvents |
| [C# IL Code Compilation Via Ilasm.EXE](rules/windows/process_creation/proc_creation_win_ilasm_il_code_compilation.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [ImagingDevices Unusual Parent/Child Processes](rules/windows/process_creation/proc_creation_win_imagingdevices_unusual_parents.kql) | high | execution, stealth | DeviceProcessEvents |
| [Arbitrary File Download Via IMEWDBLD.EXE](rules/windows/process_creation/proc_creation_win_imewbdld_download.kql) | high | execution, stealth, T1218 | DeviceProcessEvents |
| [InfDefaultInstall.exe .inf Execution](rules/windows/process_creation/proc_creation_win_infdefaultinstall_execute_sct_scripts.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [File Download Via InstallUtil.EXE](rules/windows/process_creation/proc_creation_win_installutil_download.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious Execution of InstallUtil Without Log](rules/windows/process_creation/proc_creation_win_instalutil_no_log_execution.kql) | medium | stealth | DeviceProcessEvents |
| [Suspicious Shells Spawn by Java Utility Keytool](rules/windows/process_creation/proc_creation_win_java_keytool_susp_child_process.kql) | high | initial-access, persistence, privilege-escalation | DeviceProcessEvents |
| [Suspicious Child Process Of Manage Engine ServiceDesk](rules/windows/process_creation/proc_creation_win_java_manageengine_susp_child_process.kql) | high | command-and-control, T1102 | DeviceProcessEvents |
| [Java Running with Remote Debugging](rules/windows/process_creation/proc_creation_win_java_remote_debugging.kql) | medium | T1203, execution | DeviceProcessEvents |
| [Suspicious Processes Spawned by Java.EXE](rules/windows/process_creation/proc_creation_win_java_susp_child_process.kql) | high | initial-access, persistence, privilege-escalation | DeviceProcessEvents |
| [Shell Process Spawned by Java.EXE](rules/windows/process_creation/proc_creation_win_java_susp_child_process_2.kql) | medium | initial-access, persistence, privilege-escalation | DeviceProcessEvents |
| [Suspicious SysAidServer Child](rules/windows/process_creation/proc_creation_win_java_sysaidserver_susp_child_process.kql) | medium | lateral-movement, T1210 | DeviceProcessEvents |
| [Kavremover Dropped Binary LOLBIN Usage](rules/windows/process_creation/proc_creation_win_kavremover_uncommon_execution.kql) | high | execution, stealth, T1127 | DeviceProcessEvents |
| [Windows Kernel Debugger Execution](rules/windows/process_creation/proc_creation_win_kd_execution.kql) | medium | privilege-escalation, stealth | DeviceProcessEvents |
| [Potentially Suspicious Child Process of KeyScrambler.exe](rules/windows/process_creation/proc_creation_win_keyscrambler_susp_child_process.kql) | medium | persistence, execution, privilege-escalation, stealth, T1203, T1574.001 | DeviceProcessEvents |
| [Computer Password Change Via Ksetup.EXE](rules/windows/process_creation/proc_creation_win_ksetup_password_change_computer.kql) | medium | execution | DeviceProcessEvents |
| [Logged-On User Password Change Via Ksetup.EXE](rules/windows/process_creation/proc_creation_win_ksetup_password_change_user.kql) | medium | execution | DeviceProcessEvents |
| [Active Directory Structure Export Via Ldifde.EXE](rules/windows/process_creation/proc_creation_win_ldifde_export.kql) | medium | exfiltration | DeviceProcessEvents |
| [Import LDAP Data Interchange Format File Via Ldifde.EXE](rules/windows/process_creation/proc_creation_win_ldifde_file_load.kql) | medium | command-and-control, stealth, T1218, T1105 | DeviceProcessEvents |
| [Uncommon Link.EXE Parent Process](rules/windows/process_creation/proc_creation_win_link_uncommon_parent_process.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Rebuild Performance Counter Values Via Lodctr.EXE](rules/windows/process_creation/proc_creation_win_lodctr_performance_counter_tampering.kql) | medium | execution | DeviceProcessEvents |
| [Suspicious Windows Trace ETW Session Tamper Via Logman.EXE](rules/windows/process_creation/proc_creation_win_logman_disable_eventlog.kql) | high | defense-impairment, T1685, T1685.005 | DeviceProcessEvents |
| [LOLBAS Data Exfiltration by DataSvcUtil.exe](rules/windows/process_creation/proc_creation_win_lolbin_data_exfiltration_by_using_datasvcutil.kql) | medium | exfiltration, T1567 | DeviceProcessEvents |
| [Devtoolslauncher.exe Executes Specified Binary](rules/windows/process_creation/proc_creation_win_lolbin_devtoolslauncher.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Suspicious Diantz Alternate Data Stream Execution](rules/windows/process_creation/proc_creation_win_lolbin_diantz_ads.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Suspicious Diantz Download and Compress Into a CAB File](rules/windows/process_creation/proc_creation_win_lolbin_diantz_remote_cab.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Extrac32 Execution](rules/windows/process_creation/proc_creation_win_lolbin_extrac32.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Extrac32 Alternate Data Stream Execution](rules/windows/process_creation/proc_creation_win_lolbin_extrac32_ads.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Potential Reconnaissance Activity Via GatherNetworkInfo.VBS](rules/windows/process_creation/proc_creation_win_lolbin_gather_network_info.kql) | medium | discovery, execution, T1615, T1059.005 | DeviceProcessEvents |
| [Gpscript Execution](rules/windows/process_creation/proc_creation_win_lolbin_gpscript.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Launch-VsDevShell.PS1 Proxy Execution](rules/windows/process_creation/proc_creation_win_lolbin_launch_vsdevshell.kql) | medium | stealth, T1216.001 | DeviceProcessEvents |
| [Potential Manage-bde.wsf Abuse To Proxy Execution](rules/windows/process_creation/proc_creation_win_lolbin_manage_bde.kql) | high | stealth, T1216 | DeviceProcessEvents |
| [Mavinject Inject DLL Into Running Process](rules/windows/process_creation/proc_creation_win_lolbin_mavinject_process_injection.kql) | high | privilege-escalation, stealth, T1055.001, T1218.013 | DeviceProcessEvents |
| [Execute Files with Msdeploy.exe](rules/windows/process_creation/proc_creation_win_lolbin_msdeploy.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Use of OpenConsole](rules/windows/process_creation/proc_creation_win_lolbin_openconsole.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [OpenWith.exe Executes Specified Binary](rules/windows/process_creation/proc_creation_win_lolbin_openwith.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Use of Pcalua For Execution](rules/windows/process_creation/proc_creation_win_lolbin_pcalua.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Execute Pcwrun.EXE To Leverage Follina](rules/windows/process_creation/proc_creation_win_lolbin_pcwrun_follina.kql) | high | stealth, T1218, execution | DeviceProcessEvents |
| [Code Execution via Pcwutl.dll](rules/windows/process_creation/proc_creation_win_lolbin_pcwutl.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Execute Code with Pester.bat as Parent](rules/windows/process_creation/proc_creation_win_lolbin_pester.kql) | medium | execution, stealth, T1059.001, T1216 | DeviceProcessEvents |
| [Execute Code with Pester.bat](rules/windows/process_creation/proc_creation_win_lolbin_pester_1.kql) | medium | execution, stealth, T1059.001, T1216 | DeviceProcessEvents |
| [PrintBrm ZIP Creation of Extraction](rules/windows/process_creation/proc_creation_win_lolbin_printbrm.kql) | high | command-and-control, stealth, T1105, T1564.004 | DeviceProcessEvents |
| [Pubprn.vbs Proxy Execution](rules/windows/process_creation/proc_creation_win_lolbin_pubprn.kql) | medium | stealth, T1216.001 | DeviceProcessEvents |
| [DLL Execution via Rasautou.exe](rules/windows/process_creation/proc_creation_win_lolbin_rasautou_dll_execution.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [REGISTER_APP.VBS Proxy Execution](rules/windows/process_creation/proc_creation_win_lolbin_register_app.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Use of Remote.exe](rules/windows/process_creation/proc_creation_win_lolbin_remote.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [Replace.exe Usage](rules/windows/process_creation/proc_creation_win_lolbin_replace.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Lolbin Runexehelper Use As Proxy](rules/windows/process_creation/proc_creation_win_lolbin_runexehelper.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious Runscripthelper.exe](rules/windows/process_creation/proc_creation_win_lolbin_runscripthelper.kql) | medium | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Use of Scriptrunner.exe](rules/windows/process_creation/proc_creation_win_lolbin_scriptrunner.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Using SettingSyncHost.exe as LOLBin](rules/windows/process_creation/proc_creation_win_lolbin_settingsynchost.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.008 | DeviceProcessEvents |
| [Use Of The SFTP.EXE Binary As A LOLBIN](rules/windows/process_creation/proc_creation_win_lolbin_sftp.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Suspicious Driver Install by pnputil.exe](rules/windows/process_creation/proc_creation_win_lolbin_susp_driver_installed_by_pnputil.kql) | medium | privilege-escalation, persistence, T1547 | DeviceProcessEvents |
| [Suspicious GrpConv Execution](rules/windows/process_creation/proc_creation_win_lolbin_susp_grpconv.kql) | high | privilege-escalation, persistence, T1547 | DeviceProcessEvents |
| [Dumping Process via Sqldumper.exe](rules/windows/process_creation/proc_creation_win_lolbin_susp_sqldumper_activity.kql) | medium | credential-access, T1003.001 | DeviceProcessEvents |
| [SyncAppvPublishingServer Execute Arbitrary PowerShell Code](rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_execute_psh.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code](rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh.kql) | medium | stealth, T1218, T1216 | DeviceProcessEvents |
| [Potential DLL Injection Or Execution Using Tracker.exe](rules/windows/process_creation/proc_creation_win_lolbin_tracker.kql) | medium | privilege-escalation, stealth, T1055.001 | DeviceProcessEvents |
| [Use of TTDInject.exe](rules/windows/process_creation/proc_creation_win_lolbin_ttdinject.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [Time Travel Debugging Utility Usage](rules/windows/process_creation/proc_creation_win_lolbin_tttracer_mod_load.kql) | high | credential-access, stealth, T1218, T1003.001 | DeviceProcessEvents |
| [Lolbin Unregmp2.exe Use As Proxy](rules/windows/process_creation/proc_creation_win_lolbin_unregmp2.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [UtilityFunctions.ps1 Proxy Dll](rules/windows/process_creation/proc_creation_win_lolbin_utilityfunctions.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [Visual Basic Command Line Compiler Usage](rules/windows/process_creation/proc_creation_win_lolbin_visual_basic_compiler.kql) | high | stealth, T1027.004 | DeviceProcessEvents |
| [Use of VisualUiaVerifyNative.exe](rules/windows/process_creation/proc_creation_win_lolbin_visualuiaverifynative.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Use of VSIISExeLauncher.exe](rules/windows/process_creation/proc_creation_win_lolbin_vsiisexelauncher.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [Use of Wfc.exe](rules/windows/process_creation/proc_creation_win_lolbin_wfc.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [Potential Register_App.Vbs LOLScript Abuse](rules/windows/process_creation/proc_creation_win_lolscript_register_app.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [LSA PPL Protection Setting Modification via CommandLine](rules/windows/process_creation/proc_creation_win_lsa_ppl_protection_setting_modification_via_cli.kql) | medium | defense-impairment, T1689 | DeviceProcessEvents |
| [Potential Credential Dumping Via LSASS Process Clone](rules/windows/process_creation/proc_creation_win_lsass_process_clone.kql) | critical | credential-access, T1003, T1003.001 | DeviceProcessEvents |
| [Potential Mftrace.EXE Abuse](rules/windows/process_creation/proc_creation_win_mftrace_child_process.kql) | medium | execution, stealth, T1127 | DeviceProcessEvents |
| [MMC20 Lateral Movement](rules/windows/process_creation/proc_creation_win_mmc_mmc20_lateral_movement.kql) | high | execution, lateral-movement, T1021.003 | DeviceProcessEvents |
| [MMC Spawning Windows Shell](rules/windows/process_creation/proc_creation_win_mmc_susp_child_process.kql) | high | lateral-movement, T1021.003 | DeviceProcessEvents |
| [CodePage Modification Via MODE.COM To Russian Language](rules/windows/process_creation/proc_creation_win_mode_codepage_russian.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [Potentially Suspicious Mofcomp Execution](rules/windows/process_creation/proc_creation_win_mofcomp_execution.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Potential Mpclient.DLL Sideloading Via Defender Binaries](rules/windows/process_creation/proc_creation_win_mpcmdrun_dll_sideload_defender.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [File Download Via Windows Defender MpCmpRun.EXE](rules/windows/process_creation/proc_creation_win_mpcmdrun_download_arbitrary_file.kql) | high | stealth, T1218, command-and-control, T1105 | DeviceProcessEvents |
| [Windows Defender Definition Files Removed](rules/windows/process_creation/proc_creation_win_mpcmdrun_remove_windows_defender_definition.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Suspicious Msbuild Execution By Uncommon Parent Process](rules/windows/process_creation/proc_creation_win_msbuild_susp_parent_process.kql) | medium | stealth | DeviceProcessEvents |
| [MSDT Execution Via Answer File](rules/windows/process_creation/proc_creation_win_msdt_answer_file_exec.kql) | high | stealth, T1218, execution | DeviceProcessEvents |
| [Potential Arbitrary Command Execution Using Msdt.EXE](rules/windows/process_creation/proc_creation_win_msdt_arbitrary_command_execution.kql) | high | stealth, T1202 | DeviceProcessEvents |
| [Suspicious Cabinet File Execution Via Msdt.EXE](rules/windows/process_creation/proc_creation_win_msdt_susp_cab_options.kql) | medium | stealth, T1202 | DeviceProcessEvents |
| [Suspicious MSDT Parent Process](rules/windows/process_creation/proc_creation_win_msdt_susp_parent.kql) | high | stealth, T1036, T1218 | DeviceProcessEvents |
| [Arbitrary File Download Via MSEDGE_PROXY.EXE](rules/windows/process_creation/proc_creation_win_msedge_proxy_download.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Remotely Hosted HTA File Executed Via Mshta.EXE](rules/windows/process_creation/proc_creation_win_mshta_http.kql) | high | execution, stealth, T1218.005 | DeviceProcessEvents |
| [Wscript Shell Run In CommandLine](rules/windows/process_creation/proc_creation_win_mshta_inline_vbscript.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Suspicious JavaScript Execution Via Mshta.EXE](rules/windows/process_creation/proc_creation_win_mshta_javascript.kql) | high | stealth, T1218.005 | DeviceProcessEvents |
| [Potential LethalHTA Technique Execution](rules/windows/process_creation/proc_creation_win_mshta_lethalhta_technique.kql) | high | stealth, T1218.005 | DeviceProcessEvents |
| [Suspicious MSHTA Child Process](rules/windows/process_creation/proc_creation_win_mshta_susp_child_processes.kql) | high | stealth, T1218.005 | DeviceProcessEvents |
| [MSHTA Execution with Suspicious File Extensions](rules/windows/process_creation/proc_creation_win_mshta_susp_execution.kql) | high | stealth, T1140, T1218.005, execution, T1059.007 | DeviceProcessEvents |
| [Suspicious Mshta.EXE Execution Patterns](rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.kql) | high | execution, T1106 | DeviceProcessEvents |
| [DllUnregisterServer Function Call Via Msiexec.EXE](rules/windows/process_creation/proc_creation_win_msiexec_dll.kql) | medium | stealth, T1218.007 | DeviceProcessEvents |
| [Suspicious MsiExec Embedding Parent](rules/windows/process_creation/proc_creation_win_msiexec_embedding.kql) | medium | stealth, T1218.007 | DeviceProcessEvents |
| [Suspicious Msiexec Execute Arbitrary DLL](rules/windows/process_creation/proc_creation_win_msiexec_execute_dll.kql) | medium | stealth, T1218.007 | DeviceProcessEvents |
| [Msiexec Quiet Installation](rules/windows/process_creation/proc_creation_win_msiexec_install_quiet.kql) | medium | stealth, T1218.007 | DeviceProcessEvents |
| [Suspicious Msiexec Quiet Install From Remote Location](rules/windows/process_creation/proc_creation_win_msiexec_install_remote.kql) | medium | stealth, T1218.007 | DeviceProcessEvents |
| [Potential MsiExec Masquerading](rules/windows/process_creation/proc_creation_win_msiexec_masquerading.kql) | high | stealth, T1036.005 | DeviceProcessEvents |
| [MsiExec Web Install](rules/windows/process_creation/proc_creation_win_msiexec_web_install.kql) | medium | stealth, T1218.007, command-and-control, T1105 | DeviceProcessEvents |
| [Arbitrary File Download Via MSOHTMED.EXE](rules/windows/process_creation/proc_creation_win_msohtmed_download.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Arbitrary File Download Via MSPUB.EXE](rules/windows/process_creation/proc_creation_win_mspub_download.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Potential Process Injection Via Msra.EXE](rules/windows/process_creation/proc_creation_win_msra_process_injection.kql) | high | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [Detection of PowerShell Execution via Sqlps.exe](rules/windows/process_creation/proc_creation_win_mssql_sqlps_susp_execution.kql) | medium | execution, stealth, T1059.001, T1127 | DeviceProcessEvents |
| [SQL Client Tools PowerShell Session Detection](rules/windows/process_creation/proc_creation_win_mssql_sqltoolsps_susp_execution.kql) | medium | execution, stealth, T1059.001, T1127 | DeviceProcessEvents |
| [Suspicious Child Process Of SQL Server](rules/windows/process_creation/proc_creation_win_mssql_susp_child_process.kql) | high | T1505.003, T1190, initial-access, persistence, privilege-escalation | DeviceProcessEvents |
| [Suspicious Child Process Of Veeam Dabatase](rules/windows/process_creation/proc_creation_win_mssql_veaam_susp_child_processes.kql) | critical | initial-access, persistence, privilege-escalation | DeviceProcessEvents |
| [Potential MSTSC Shadowing Activity](rules/windows/process_creation/proc_creation_win_mstsc_rdp_hijack_shadowing.kql) | high | lateral-movement, T1563.002 | DeviceProcessEvents |
| [New Remote Desktop Connection Initiated Via Mstsc.EXE](rules/windows/process_creation/proc_creation_win_mstsc_remote_connection.kql) | medium | lateral-movement, T1021.001 | DeviceProcessEvents |
| [Suspicious Mstsc.EXE Execution With Local RDP File](rules/windows/process_creation/proc_creation_win_mstsc_run_local_rdp_file_susp_location.kql) | high | command-and-control, T1219.002 | DeviceProcessEvents |
| [Mstsc.EXE Execution From Uncommon Parent](rules/windows/process_creation/proc_creation_win_mstsc_run_local_rpd_file_susp_parent.kql) | high | lateral-movement | DeviceProcessEvents |
| [Msxsl.EXE Execution](rules/windows/process_creation/proc_creation_win_msxsl_execution.kql) | medium | stealth, T1220 | DeviceProcessEvents |
| [Remote XSL Execution Via Msxsl.EXE](rules/windows/process_creation/proc_creation_win_msxsl_remote_execution.kql) | high | stealth, T1220 | DeviceProcessEvents |
| [Suspicious Group And Account Reconnaissance Activity Using Net.EXE](rules/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon.kql) | medium | discovery, T1087.001, T1087.002 | DeviceProcessEvents |
| [Windows Admin Share Mount Via Net.EXE](rules/windows/process_creation/proc_creation_win_net_use_mount_admin_share.kql) | medium | lateral-movement, T1021.002 | DeviceProcessEvents |
| [Windows Internet Hosted WebDav Share Mount Via Net.EXE](rules/windows/process_creation/proc_creation_win_net_use_mount_internet_share.kql) | high | lateral-movement, T1021.002 | DeviceProcessEvents |
| [Password Provided In Command Line Of Net.EXE](rules/windows/process_creation/proc_creation_win_net_use_password_plaintext.kql) | medium | initial-access, persistence, privilege-escalation, lateral-movement, stealth, T1021.002, T1078 | DeviceProcessEvents |
| [New User Created Via Net.EXE](rules/windows/process_creation/proc_creation_win_net_user_add.kql) | medium | persistence, T1136.001 | DeviceProcessEvents |
| [New User Created Via Net.EXE With Never Expire Option](rules/windows/process_creation/proc_creation_win_net_user_add_never_expire.kql) | high | persistence, T1136.001 | DeviceProcessEvents |
| [Suspicious Manipulation Of Default Accounts Via Net.EXE](rules/windows/process_creation/proc_creation_win_net_user_default_accounts_manipulation.kql) | high | collection, T1560.001 | DeviceProcessEvents |
| [New Firewall Rule Added Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_fw_add_rule.kql) | medium | defense-impairment, T1686.003, S0246 | DeviceProcessEvents |
| [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_fw_allow_program_in_susp_location.kql) | high | defense-impairment, T1686.003 | DeviceProcessEvents |
| [RDP Connection Allowed Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_fw_allow_rdp.kql) | high | defense-impairment, T1686.003 | DeviceProcessEvents |
| [Firewall Rule Deleted Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_fw_delete_rule.kql) | medium | defense-impairment, T1686.003 | DeviceProcessEvents |
| [Firewall Disabled via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_fw_disable.kql) | medium | defense-impairment, T1686.003, S0108 | DeviceProcessEvents |
| [Netsh Allow Group Policy on Microsoft Defender Firewall](rules/windows/process_creation/proc_creation_win_netsh_fw_enable_group_rule.kql) | medium | defense-impairment, T1686.003 | DeviceProcessEvents |
| [Firewall Rule Update Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_fw_set_rule.kql) | medium | defense-impairment | DeviceProcessEvents |
| [Potential Persistence Via Netsh Helper DLL](rules/windows/process_creation/proc_creation_win_netsh_helper_dll_persistence.kql) | medium | privilege-escalation, persistence, T1546.007, S0108 | DeviceProcessEvents |
| [New Network Trace Capture Started Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_packet_capture.kql) | medium | discovery, credential-access, T1040 | DeviceProcessEvents |
| [New Port Forwarding Rule Added Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_port_forwarding.kql) | medium | lateral-movement, command-and-control, T1090 | DeviceProcessEvents |
| [RDP Port Forwarding Rule Added Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_port_forwarding_3389.kql) | high | lateral-movement, command-and-control, T1090 | DeviceProcessEvents |
| [Harvesting Of Wifi Credentials Via Netsh.EXE](rules/windows/process_creation/proc_creation_win_netsh_wifi_credential_harvesting.kql) | medium | discovery, credential-access, T1040 | DeviceProcessEvents |
| [Potential Recon Activity Via Nltest.EXE](rules/windows/process_creation/proc_creation_win_nltest_recon.kql) | medium | discovery, T1016, T1482 | DeviceProcessEvents |
| [Potential Arbitrary Code Execution Via Node.EXE](rules/windows/process_creation/proc_creation_win_node_abuse.kql) | high | execution, stealth, T1127 | DeviceProcessEvents |
| [Node Process Executions](rules/windows/process_creation/proc_creation_win_node_adobe_creative_cloud_abuse.kql) | medium | execution, stealth, T1127, T1059.007 | DeviceProcessEvents |
| [Network Reconnaissance Activity](rules/windows/process_creation/proc_creation_win_nslookup_domain_discovery.kql) | high | discovery, T1087, T1082 | DeviceProcessEvents |
| [Nslookup PowerShell Download Cradle - ProcessCreation](rules/windows/process_creation/proc_creation_win_nslookup_poweshell_download.kql) | medium | command-and-control, T1071.004 | DeviceProcessEvents |
| [Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe)](rules/windows/process_creation/proc_creation_win_ntdsutil_susp_usage.kql) | medium | credential-access, T1003.003 | DeviceProcessEvents |
| [Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)](rules/windows/process_creation/proc_creation_win_ntdsutil_usage.kql) | medium | credential-access, T1003.003 | DeviceProcessEvents |
| [Driver/DLL Installation Via Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_driver_install.kql) | medium | stealth, T1218.008 | DeviceProcessEvents |
| [Suspicious Driver/DLL Installation Via Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_driver_install_susp.kql) | high | stealth, T1218.008 | DeviceProcessEvents |
| [Odbcconf.EXE Suspicious DLL Location](rules/windows/process_creation/proc_creation_win_odbcconf_exec_susp_locations.kql) | high | stealth, T1218.008 | DeviceProcessEvents |
| [New DLL Registered Via Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_register_dll_regsvr.kql) | medium | stealth, T1218.008 | DeviceProcessEvents |
| [Potentially Suspicious DLL Registered Via Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_register_dll_regsvr_susp.kql) | high | stealth, T1218.008 | DeviceProcessEvents |
| [Response File Execution Via Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_response_file.kql) | medium | stealth, T1218.008 | DeviceProcessEvents |
| [Suspicious Response File Execution Via Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_response_file_susp.kql) | high | stealth, T1218.008 | DeviceProcessEvents |
| [Uncommon Child Process Spawned By Odbcconf.EXE](rules/windows/process_creation/proc_creation_win_odbcconf_uncommon_child_process.kql) | medium | stealth, T1218.008 | DeviceProcessEvents |
| [Potential Arbitrary File Download Using Office Application](rules/windows/process_creation/proc_creation_win_office_arbitrary_cli_download.kql) | high | stealth, T1202 | DeviceProcessEvents |
| [Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp](rules/windows/process_creation/proc_creation_win_office_excel_dcom_lateral_movement.kql) | high | T1021.003, lateral-movement | DeviceProcessEvents |
| [Potentially Suspicious Office Document Executed From Trusted Location](rules/windows/process_creation/proc_creation_win_office_exec_from_trusted_locations.kql) | high | stealth, T1202 | DeviceProcessEvents |
| [OneNote.EXE Execution of Malicious Embedded Scripts](rules/windows/process_creation/proc_creation_win_office_onenote_embedded_script_execution.kql) | high | stealth, T1218.001 | DeviceProcessEvents |
| [Suspicious Microsoft OneNote Child Process](rules/windows/process_creation/proc_creation_win_office_onenote_susp_child_processes.kql) | high | T1566, T1566.001, initial-access | DeviceProcessEvents |
| [Outlook EnableUnsafeClientMailRules Setting Enabled](rules/windows/process_creation/proc_creation_win_office_outlook_enable_unsafe_client_mail_rules.kql) | high | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Suspicious Execution From Outlook Temporary Folder](rules/windows/process_creation/proc_creation_win_office_outlook_execution_from_temp.kql) | high | initial-access, T1566.001 | DeviceProcessEvents |
| [Suspicious Outlook Child Process](rules/windows/process_creation/proc_creation_win_office_outlook_susp_child_processes.kql) | high | execution, T1204.002 | DeviceProcessEvents |
| [Suspicious Remote Child Process From Outlook](rules/windows/process_creation/proc_creation_win_office_outlook_susp_child_processes_remote.kql) | high | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Suspicious Binary In User Directory Spawned From Office Application](rules/windows/process_creation/proc_creation_win_office_spawn_exe_from_users_directory.kql) | high | execution, T1204.002, G0046 | DeviceProcessEvents |
| [Suspicious Microsoft Office Child Process](rules/windows/process_creation/proc_creation_win_office_susp_child_processes.kql) | high | execution, stealth, T1047, T1204.002, T1218.010 | DeviceProcessEvents |
| [Potential Arbitrary DLL Load Using Winword](rules/windows/process_creation/proc_creation_win_office_winword_dll_load.kql) | medium | stealth, T1202 | DeviceProcessEvents |
| [PDQ Deploy Remote Adminstartion Tool Execution](rules/windows/process_creation/proc_creation_win_pdqdeploy_execution.kql) | medium | execution, lateral-movement, T1072 | DeviceProcessEvents |
| [Potentially Suspicious Execution Of PDQDeployRunner](rules/windows/process_creation/proc_creation_win_pdqdeploy_runner_susp_children.kql) | medium | execution | DeviceProcessEvents |
| [Perl Inline Command Execution](rules/windows/process_creation/proc_creation_win_perl_inline_command_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Php Inline Command Execution](rules/windows/process_creation/proc_creation_win_php_inline_command_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Ping Hex IP](rules/windows/process_creation/proc_creation_win_ping_hex_ip.kql) | high | stealth, T1140, T1027 | DeviceProcessEvents |
| [PktMon.EXE Execution](rules/windows/process_creation/proc_creation_win_pktmon_execution.kql) | medium | discovery, credential-access, T1040 | DeviceProcessEvents |
| [Suspicious Plink Port Forwarding](rules/windows/process_creation/proc_creation_win_plink_port_forwarding.kql) | high | command-and-control, T1572, lateral-movement, T1021.001 | DeviceProcessEvents |
| [Potential RDP Tunneling Via Plink](rules/windows/process_creation/proc_creation_win_plink_susp_tunneling.kql) | high | command-and-control, T1572 | DeviceProcessEvents |
| [Suspicious Powercfg Execution To Change Lock Screen Timeout](rules/windows/process_creation/proc_creation_win_powercfg_execution.kql) | medium | stealth | DeviceProcessEvents |
| [AADInternals PowerShell Cmdlets Execution - ProccessCreation](rules/windows/process_creation/proc_creation_win_powershell_aadinternals_cmdlets_execution.kql) | high | execution, reconnaissance, discovery, credential-access, impact | DeviceProcessEvents |
| [Potential Active Directory Enumeration Using AD Module - ProcCreation](rules/windows/process_creation/proc_creation_win_powershell_active_directory_module_dll_import.kql) | medium | reconnaissance, discovery, impact | DeviceProcessEvents |
| [Add Windows Capability Via PowerShell Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_add_windows_capability.kql) | medium | execution | DeviceProcessEvents |
| [Potential AMSI Bypass Via .NET Reflection](rules/windows/process_creation/proc_creation_win_powershell_amsi_init_failed_bypass.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential AMSI Bypass Using NULL Bits](rules/windows/process_creation/proc_creation_win_powershell_amsi_null_bits_bypass.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [Audio Capture via PowerShell](rules/windows/process_creation/proc_creation_win_powershell_audio_capture.kql) | medium | collection, T1123 | DeviceProcessEvents |
| [Suspicious Encoded PowerShell Command Line](rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Suspicious PowerShell Encoded Command Patterns](rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd_patterns.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Suspicious Obfuscated PowerShell Code](rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_obfusc.kql) | high | stealth | DeviceProcessEvents |
| [PowerShell Base64 Encoded FromBase64String Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_base64_frombase64string.kql) | high | stealth, T1140, execution, T1059.001 | DeviceProcessEvents |
| [Malicious Base64 Encoded PowerShell Keywords in Command Lines](rules/windows/process_creation/proc_creation_win_powershell_base64_hidden_flag.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [PowerShell Base64 Encoded IEX Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_base64_iex.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [PowerShell Base64 Encoded Invoke Keyword](rules/windows/process_creation/proc_creation_win_powershell_base64_invoke.kql) | high | execution, stealth, T1059.001, T1027 | DeviceProcessEvents |
| [Powershell Base64 Encoded MpPreference Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_base64_mppreference.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [PowerShell Base64 Encoded Reflective Assembly Load](rules/windows/process_creation/proc_creation_win_powershell_base64_reflection_assembly_load.kql) | high | execution, stealth, T1059.001, T1027, T1620 | DeviceProcessEvents |
| [Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call](rules/windows/process_creation/proc_creation_win_powershell_base64_reflection_assembly_load_obfusc.kql) | high | execution, stealth, T1059.001, T1027 | DeviceProcessEvents |
| [PowerShell Base64 Encoded WMI Classes](rules/windows/process_creation/proc_creation_win_powershell_base64_wmi_classes.kql) | high | execution, stealth, T1059.001, T1027 | DeviceProcessEvents |
| [Potential Process Execution Proxy Via CL_Invocation.ps1](rules/windows/process_creation/proc_creation_win_powershell_cl_invocation.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [Assembly Loading Via CL_LoadAssembly.ps1](rules/windows/process_creation/proc_creation_win_powershell_cl_loadassembly.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [Potential Script Proxy Execution Via CL_Mutexverifiers.ps1](rules/windows/process_creation/proc_creation_win_powershell_cl_mutexverifiers.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [ConvertTo-SecureString Cmdlet Usage Via CommandLine](rules/windows/process_creation/proc_creation_win_powershell_cmdline_convertto_securestring.kql) | medium | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Potential PowerShell Obfuscation Via Reversed Commands](rules/windows/process_creation/proc_creation_win_powershell_cmdline_reversed_strings.kql) | high | stealth, T1027, execution, T1059.001 | DeviceProcessEvents |
| [Potential PowerShell Command Line Obfuscation](rules/windows/process_creation/proc_creation_win_powershell_cmdline_special_characters.kql) | high | execution, stealth, T1027, T1059.001 | DeviceProcessEvents |
| [Computer Discovery And Export Via Get-ADComputer Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_computer_discovery_get_adcomputer.kql) | medium | discovery, T1033 | DeviceProcessEvents |
| [Gzip Archive Decode Via PowerShell](rules/windows/process_creation/proc_creation_win_powershell_decode_gzip.kql) | medium | command-and-control, T1132.001 | DeviceProcessEvents |
| [PowerShell Execution With Potential Decryption Capabilities](rules/windows/process_creation/proc_creation_win_powershell_decrypt_pattern.kql) | high | execution | DeviceProcessEvents |
| [Powershell Defender Disable Scan Feature](rules/windows/process_creation/proc_creation_win_powershell_defender_disable_feature.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Powershell Defender Exclusion](rules/windows/process_creation/proc_creation_win_powershell_defender_exclusion.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [Disable Windows Defender AV Security Monitoring](rules/windows/process_creation/proc_creation_win_powershell_disable_defender_av_security_monitoring.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Windows Firewall Disabled via PowerShell](rules/windows/process_creation/proc_creation_win_powershell_disable_firewall.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [Disabled IE Security Features](rules/windows/process_creation/proc_creation_win_powershell_disable_ie_features.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential PowerShell Downgrade Attack](rules/windows/process_creation/proc_creation_win_powershell_downgrade_attack.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Potential COM Objects Download Cradles Usage - Process Creation](rules/windows/process_creation/proc_creation_win_powershell_download_com_cradles.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Obfuscated PowerShell OneLiner Execution](rules/windows/process_creation/proc_creation_win_powershell_download_cradle_obfuscated.kql) | high | execution, defense-impairment, T1059.001, T1685 | DeviceProcessEvents |
| [Potential DLL File Download Via PowerShell Invoke-WebRequest](rules/windows/process_creation/proc_creation_win_powershell_download_dll.kql) | medium | command-and-control, execution, T1059.001, T1105 | DeviceProcessEvents |
| [PowerShell Download and Execution Cradles](rules/windows/process_creation/proc_creation_win_powershell_download_iex.kql) | high | execution, T1059 | DeviceProcessEvents |
| [PowerShell Download Pattern](rules/windows/process_creation/proc_creation_win_powershell_download_patterns.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE](rules/windows/process_creation/proc_creation_win_powershell_download_susp_file_sharing_domains.kql) | high | execution | DeviceProcessEvents |
| [DSInternals Suspicious PowerShell Cmdlets](rules/windows/process_creation/proc_creation_win_powershell_dsinternals_cmdlets.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Email Exifiltration Via Powershell](rules/windows/process_creation/proc_creation_win_powershell_email_exfil.kql) | high | exfiltration | DeviceProcessEvents |
| [Potential Suspicious Windows Feature Enabled - ProcCreation](rules/windows/process_creation/proc_creation_win_powershell_enable_susp_windows_optional_feature.kql) | medium | stealth | DeviceProcessEvents |
| [Suspicious Execution of Powershell with Base64](rules/windows/process_creation/proc_creation_win_powershell_encode.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Powershell Inline Execution From A File](rules/windows/process_creation/proc_creation_win_powershell_exec_data_file.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Certificate Exported Via PowerShell](rules/windows/process_creation/proc_creation_win_powershell_export_certificate.kql) | medium | credential-access, execution, T1552.004, T1059.001 | DeviceProcessEvents |
| [Base64 Encoded PowerShell Command Detected](rules/windows/process_creation/proc_creation_win_powershell_frombase64string.kql) | high | stealth, T1027, execution, T1140, T1059.001 | DeviceProcessEvents |
| [Suspicious FromBase64String Usage On Gzip Archive - Process Creation](rules/windows/process_creation/proc_creation_win_powershell_frombase64string_archive.kql) | medium | command-and-control, T1132.001 | DeviceProcessEvents |
| [PowerShell Get-Clipboard Cmdlet Via CLI](rules/windows/process_creation/proc_creation_win_powershell_get_clipboard.kql) | medium | collection, T1115 | DeviceProcessEvents |
| [Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_get_localgroup_member_recon.kql) | medium | discovery, T1087.001 | DeviceProcessEvents |
| [PowerShell Get-Process LSASS](rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.kql) | high | credential-access, T1552.004 | DeviceProcessEvents |
| [Abuse of Service Permissions to Hide Services Via Set-Service](rules/windows/process_creation/proc_creation_win_powershell_hide_services_via_set_service.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.011 | DeviceProcessEvents |
| [Suspicious PowerShell IEX Execution Patterns](rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Root Certificate Installed From Susp Locations](rules/windows/process_creation/proc_creation_win_powershell_import_cert_susp_locations.kql) | high | defense-impairment, T1553.004 | DeviceProcessEvents |
| [Import PowerShell Modules From Suspicious Directories - ProcCreation](rules/windows/process_creation/proc_creation_win_powershell_import_module_susp_dirs.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Unsigned AppX Installation Attempt Using Add-AppxPackage](rules/windows/process_creation/proc_creation_win_powershell_install_unsigned_appx_packages.kql) | medium | persistence, stealth | DeviceProcessEvents |
| [Suspicious PowerShell Invocations - Specific - ProcessCreation](rules/windows/process_creation/proc_creation_win_powershell_invocation_specific.kql) | medium | stealth | DeviceProcessEvents |
| [Suspicious Invoke-WebRequest Execution With DirectIP](rules/windows/process_creation/proc_creation_win_powershell_invoke_webrequest_direct_ip.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious Invoke-WebRequest Execution](rules/windows/process_creation/proc_creation_win_powershell_invoke_webrequest_download.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [Suspicious PowerShell Mailbox Export to Share](rules/windows/process_creation/proc_creation_win_powershell_mailboxexport_share.kql) | critical | exfiltration | DeviceProcessEvents |
| [Malicious PowerShell Commandlets - ProcessCreation](rules/windows/process_creation/proc_creation_win_powershell_malicious_cmdlets.kql) | high | execution, discovery, T1482, T1087, T1087.001, T1087.002, T1069.001, T1069.002, T1069, T1059.001 | DeviceProcessEvents |
| [MSExchange Transport Agent Installation](rules/windows/process_creation/proc_creation_win_powershell_msexchange_transport_agent.kql) | medium | persistence, T1505.002 | DeviceProcessEvents |
| [Potential PowerShell Obfuscation Via WCHAR/CHAR](rules/windows/process_creation/proc_creation_win_powershell_obfuscation_via_utf8.kql) | high | execution, stealth, T1059.001, T1027 | DeviceProcessEvents |
| [Execution of Powershell Script in Public Folder](rules/windows/process_creation/proc_creation_win_powershell_public_folder.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses](rules/windows/process_creation/proc_creation_win_powershell_remotefxvgpudisablement_abuse.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Tamper Windows Defender Remove-MpPreference](rules/windows/process_creation/proc_creation_win_powershell_remove_mppreference.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential Powershell ReverseShell Connection](rules/windows/process_creation/proc_creation_win_powershell_reverse_shell_connection.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Run PowerShell Script from ADS](rules/windows/process_creation/proc_creation_win_powershell_run_script_from_ads.kql) | high | stealth, T1564.004 | DeviceProcessEvents |
| [Run PowerShell Script from Redirected Input Stream](rules/windows/process_creation/proc_creation_win_powershell_run_script_from_input_stream.kql) | high | execution, T1059 | DeviceProcessEvents |
| [PowerShell SAM Copy](rules/windows/process_creation/proc_creation_win_powershell_sam_access.kql) | high | credential-access, T1003.002 | DeviceProcessEvents |
| [Potentially Suspicious Powershell Script Execution From Temp Folder](rules/windows/process_creation/proc_creation_win_powershell_script_exec_from_temp_folder.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Suspicious Service DACL Modification Via Set-Service Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_service_dacl_modification_set_service.kql) | high | privilege-escalation, persistence, T1543.003 | DeviceProcessEvents |
| [PowerShell Script Change Permission Via Set-Acl](rules/windows/process_creation/proc_creation_win_powershell_set_acl.kql) | high | stealth | DeviceProcessEvents |
| [PowerShell Set-Acl On Windows Folder](rules/windows/process_creation/proc_creation_win_powershell_set_acl_susp_location.kql) | high | stealth | DeviceProcessEvents |
| [Change PowerShell Policies to an Insecure Level](rules/windows/process_creation/proc_creation_win_powershell_set_policies_to_unsecure_level.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Service StartupType Change Via PowerShell Set-Service](rules/windows/process_creation/proc_creation_win_powershell_set_service_disabled.kql) | medium | execution, defense-impairment, T1685 | DeviceProcessEvents |
| [Deletion of Volume Shadow Copies via WMI with PowerShell](rules/windows/process_creation/proc_creation_win_powershell_shadowcopy_deletion.kql) | high | impact, T1490 | DeviceProcessEvents |
| [Exchange PowerShell Snap-Ins Usage](rules/windows/process_creation/proc_creation_win_powershell_snapins_hafnium.kql) | high | execution, T1059.001, collection, T1114 | DeviceProcessEvents |
| [Suspicious PowerShell Download and Execute Pattern](rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Suspicious PowerShell Parameter Substring](rules/windows/process_creation/proc_creation_win_powershell_susp_parameter_variation.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Suspicious PowerShell Parent Process](rules/windows/process_creation/proc_creation_win_powershell_susp_parent_process.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [PowerShell Script Run in AppData](rules/windows/process_creation/proc_creation_win_powershell_susp_ps_appdata.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Powershell Token Obfuscation - Process Creation](rules/windows/process_creation/proc_creation_win_powershell_token_obfuscation.kql) | high | stealth, T1027.009 | DeviceProcessEvents |
| [User Discovery And Export Via Get-ADUser Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_user_discovery_get_aduser.kql) | medium | discovery, T1033 | DeviceProcessEvents |
| [Net WebClient Casing Anomalies](rules/windows/process_creation/proc_creation_win_powershell_webclient_casing.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Suspicious X509Enrollment - Process Creation](rules/windows/process_creation/proc_creation_win_powershell_x509enrollment.kql) | medium | defense-impairment, T1553.004 | DeviceProcessEvents |
| [Suspicious XOR Encoded PowerShell Command](rules/windows/process_creation/proc_creation_win_powershell_xor_commandline.kql) | medium | execution, stealth, T1059.001, T1140, T1027 | DeviceProcessEvents |
| [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](rules/windows/process_creation/proc_creation_win_powershell_zip_compress.kql) | medium | collection, T1074.001 | DeviceProcessEvents |
| [Arbitrary File Download Via PresentationHost.EXE](rules/windows/process_creation/proc_creation_win_presentationhost_download.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [XBAP Execution From Uncommon Locations Via PresentationHost.EXE](rules/windows/process_creation/proc_creation_win_presentationhost_uncommon_location_exec.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution](rules/windows/process_creation/proc_creation_win_pressanykey_lolbin_execution.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Sensitive File Dump Via Print.EXE](rules/windows/process_creation/proc_creation_win_print_dump_sensitive_files.kql) | high | credential-access, stealth, T1003.003, T1003.002, T1218 | DeviceProcessEvents |
| [Abusing Print Executable](rules/windows/process_creation/proc_creation_win_print_remote_file_copy.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [File Download Using ProtocolHandler.exe](rules/windows/process_creation/proc_creation_win_protocolhandler_download.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential Provlaunch.EXE Binary Proxy Execution Abuse](rules/windows/process_creation/proc_creation_win_provlaunch_potential_abuse.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious Provlaunch.EXE Child Process](rules/windows/process_creation/proc_creation_win_provlaunch_susp_child_process.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Screen Capture Activity Via Psr.EXE](rules/windows/process_creation/proc_creation_win_psr_capture_screenshots.kql) | medium | collection, T1113 | DeviceProcessEvents |
| [PUA - 3Proxy Execution](rules/windows/process_creation/proc_creation_win_pua_3proxy_execution.kql) | high | command-and-control, T1572 | DeviceProcessEvents |
| [PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE](rules/windows/process_creation/proc_creation_win_pua_adfind_enumeration.kql) | high | discovery, T1087.002 | DeviceProcessEvents |
| [PUA - AdFind Suspicious Execution](rules/windows/process_creation/proc_creation_win_pua_adfind_susp_usage.kql) | high | discovery, T1018, T1087.002, T1482, T1069.002 | DeviceProcessEvents |
| [PUA - Advanced IP Scanner Execution](rules/windows/process_creation/proc_creation_win_pua_advanced_ip_scanner.kql) | medium | discovery, T1046, T1135 | DeviceProcessEvents |
| [PUA - Advanced Port Scanner Execution](rules/windows/process_creation/proc_creation_win_pua_advanced_port_scanner.kql) | medium | discovery, T1046, T1135 | DeviceProcessEvents |
| [PUA - AdvancedRun Execution](rules/windows/process_creation/proc_creation_win_pua_advancedrun.kql) | medium | execution, privilege-escalation, stealth, T1564.003, T1134.002, T1059.003 | DeviceProcessEvents |
| [PUA - AdvancedRun Suspicious Execution](rules/windows/process_creation/proc_creation_win_pua_advancedrun_priv_user.kql) | high | privilege-escalation, stealth, T1134.002 | DeviceProcessEvents |
| [PUA - Chisel Tunneling Tool Execution](rules/windows/process_creation/proc_creation_win_pua_chisel.kql) | high | command-and-control, T1090.001 | DeviceProcessEvents |
| [PUA - CleanWipe Execution](rules/windows/process_creation/proc_creation_win_pua_cleanwipe.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [PUA - Crassus Execution](rules/windows/process_creation/proc_creation_win_pua_crassus.kql) | high | discovery, reconnaissance, T1590.001 | DeviceProcessEvents |
| [PUA - CsExec Execution](rules/windows/process_creation/proc_creation_win_pua_csexec.kql) | high | resource-development, T1587.001, execution, T1569.002 | DeviceProcessEvents |
| [PUA - DefenderCheck Execution](rules/windows/process_creation/proc_creation_win_pua_defendercheck.kql) | high | stealth, T1027.005 | DeviceProcessEvents |
| [PUA - DIT Snapshot Viewer](rules/windows/process_creation/proc_creation_win_pua_ditsnap.kql) | high | credential-access, T1003.003 | DeviceProcessEvents |
| [PUA - Fast Reverse Proxy (FRP) Execution](rules/windows/process_creation/proc_creation_win_pua_frp.kql) | high | command-and-control, T1090 | DeviceProcessEvents |
| [PUA- IOX Tunneling Tool Execution](rules/windows/process_creation/proc_creation_win_pua_iox.kql) | high | command-and-control, T1090 | DeviceProcessEvents |
| [PUA - Mouse Lock Execution](rules/windows/process_creation/proc_creation_win_pua_mouselock_execution.kql) | medium | credential-access, collection, T1056.002 | DeviceProcessEvents |
| [PUA - Netcat Suspicious Execution](rules/windows/process_creation/proc_creation_win_pua_netcat.kql) | high | command-and-control, T1095 | DeviceProcessEvents |
| [PUA - SoftPerfect Netscan Execution](rules/windows/process_creation/proc_creation_win_pua_netscan.kql) | medium | discovery, T1046 | DeviceProcessEvents |
| [PUA - Ngrok Execution](rules/windows/process_creation/proc_creation_win_pua_ngrok.kql) | high | command-and-control, T1572 | DeviceProcessEvents |
| [PUA - Nimgrab Execution](rules/windows/process_creation/proc_creation_win_pua_nimgrab.kql) | high | command-and-control, T1105 | DeviceProcessEvents |
| [PUA - NirCmd Execution](rules/windows/process_creation/proc_creation_win_pua_nircmd.kql) | medium | execution, T1569.002, S0029 | DeviceProcessEvents |
| [PUA - NirCmd Execution As LOCAL SYSTEM](rules/windows/process_creation/proc_creation_win_pua_nircmd_as_system.kql) | high | execution, T1569.002, S0029 | DeviceProcessEvents |
| [PUA - Nmap/Zenmap Execution](rules/windows/process_creation/proc_creation_win_pua_nmap_zenmap.kql) | medium | discovery, T1046 | DeviceProcessEvents |
| [PUA - NPS Tunneling Tool Execution](rules/windows/process_creation/proc_creation_win_pua_nps.kql) | high | command-and-control, T1090 | DeviceProcessEvents |
| [PUA - NSudo Execution](rules/windows/process_creation/proc_creation_win_pua_nsudo.kql) | high | execution, T1569.002, S0029 | DeviceProcessEvents |
| [PUA - PingCastle Execution](rules/windows/process_creation/proc_creation_win_pua_pingcastle.kql) | medium | reconnaissance, T1595 | DeviceProcessEvents |
| [PUA - PingCastle Execution From Potentially Suspicious Parent](rules/windows/process_creation/proc_creation_win_pua_pingcastle_script_parent.kql) | high | reconnaissance, T1595 | DeviceProcessEvents |
| [PUA - Process Hacker Execution](rules/windows/process_creation/proc_creation_win_pua_process_hacker.kql) | medium | discovery, persistence, privilege-escalation, stealth, T1622, T1564, T1543 | DeviceProcessEvents |
| [PUA - Radmin Viewer Utility Execution](rules/windows/process_creation/proc_creation_win_pua_radmin.kql) | medium | execution, lateral-movement, T1072 | DeviceProcessEvents |
| [PUA - Potential PE Metadata Tamper Using Rcedit](rules/windows/process_creation/proc_creation_win_pua_rcedit_execution.kql) | medium | stealth, T1036.003, T1036, T1027.005, T1027 | DeviceProcessEvents |
| [PUA - Rclone Execution](rules/windows/process_creation/proc_creation_win_pua_rclone_execution.kql) | high | exfiltration, T1567.002 | DeviceProcessEvents |
| [PUA - RunXCmd Execution](rules/windows/process_creation/proc_creation_win_pua_runxcmd.kql) | high | execution, T1569.002, S0029 | DeviceProcessEvents |
| [PUA - Seatbelt Execution](rules/windows/process_creation/proc_creation_win_pua_seatbelt.kql) | high | discovery, T1526, T1087, T1083 | DeviceProcessEvents |
| [PUA - System Informer Execution](rules/windows/process_creation/proc_creation_win_pua_system_informer.kql) | medium | persistence, privilege-escalation, discovery, stealth, T1082, T1564, T1543 | DeviceProcessEvents |
| [PUA - WebBrowserPassView Execution](rules/windows/process_creation/proc_creation_win_pua_webbrowserpassview.kql) | medium | credential-access, T1555.003 | DeviceProcessEvents |
| [PUA - Wsudo Suspicious Execution](rules/windows/process_creation/proc_creation_win_pua_wsudo_susp_execution.kql) | high | execution, privilege-escalation, T1059 | DeviceProcessEvents |
| [Python Inline Command Execution](rules/windows/process_creation/proc_creation_win_python_inline_command_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Python Spawning Pretty TTY on Windows](rules/windows/process_creation/proc_creation_win_python_pty_spawn.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Potentially Suspicious Usage Of Qemu](rules/windows/process_creation/proc_creation_win_qemu_suspicious_execution.kql) | medium | command-and-control, T1090, T1572 | DeviceProcessEvents |
| [Query Usage To Exfil Data](rules/windows/process_creation/proc_creation_win_query_session_exfil.kql) | medium | execution | DeviceProcessEvents |
| [Rar Usage with Password and Compression Level](rules/windows/process_creation/proc_creation_win_rar_compression_with_password.kql) | high | collection, T1560.001 | DeviceProcessEvents |
| [Suspicious Greedy Compression Using Rar.EXE](rules/windows/process_creation/proc_creation_win_rar_susp_greedy_compression.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Suspicious RASdial Activity](rules/windows/process_creation/proc_creation_win_rasdial_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Process Memory Dump via RdrLeakDiag.EXE](rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.kql) | high | credential-access, T1003.001 | DeviceProcessEvents |
| [Potential Persistence Attempt Via Run Keys Using Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_add_run_key.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceProcessEvents |
| [Add SafeBoot Keys Via Reg Utility](rules/windows/process_creation/proc_creation_win_reg_add_safeboot.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Suspicious Reg Add BitLocker](rules/windows/process_creation/proc_creation_win_reg_bitlocker.kql) | high | impact, T1486 | DeviceProcessEvents |
| [Dropping Of Password Filter DLL](rules/windows/process_creation/proc_creation_win_reg_credential_access_via_password_filter.kql) | medium | persistence, credential-access, defense-impairment, T1556.002 | DeviceProcessEvents |
| [Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_defender_exclusion.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [SafeBoot Registry Key Deleted Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_delete_safeboot.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Service Registry Key Deleted Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_delete_services.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potentially Suspicious Desktop Background Change Using Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_desktop_background_change.kql) | medium | persistence, impact, defense-impairment, T1112, T1491.001 | DeviceProcessEvents |
| [Direct Autorun Keys Modification](rules/windows/process_creation/proc_creation_win_reg_direct_asep_registry_keys_modification.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceProcessEvents |
| [Security Service Disabled Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_disable_sec_services.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Dumping of Sensitive Hives Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.kql) | high | credential-access, T1003.002, T1003.004, T1003.005 | DeviceProcessEvents |
| [Windows Recall Feature Enabled Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_enable_windows_recall.kql) | medium | collection, T1113 | DeviceProcessEvents |
| [Enumeration for Credentials in Registry](rules/windows/process_creation/proc_creation_win_reg_enumeration_for_credentials_in_registry.kql) | medium | credential-access, T1552.002 | DeviceProcessEvents |
| [Potential Suspicious Registry File Imported Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_import_from_suspicious_paths.kql) | medium | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [RestrictedAdminMode Registry Value Tampering - ProcCreation](rules/windows/process_creation/proc_creation_win_reg_lsa_disable_restricted_admin.kql) | high | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Modify Group Policy Settings](rules/windows/process_creation/proc_creation_win_reg_modify_group_policy_settings.kql) | medium | privilege-escalation, defense-impairment, T1484.001 | DeviceProcessEvents |
| [Enable LM Hash Storage - ProcCreation](rules/windows/process_creation/proc_creation_win_reg_nolmhash.kql) | high | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Potential Configuration And Service Reconnaissance Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_query_registry.kql) | medium | discovery, T1012, T1007 | DeviceProcessEvents |
| [Potential Tampering With RDP Related Registry Keys Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_rdp_keys_tamper.kql) | high | persistence, lateral-movement, defense-impairment, T1021.001, T1112 | DeviceProcessEvents |
| [Suspicious ScreenSave Change by Reg.exe](rules/windows/process_creation/proc_creation_win_reg_screensaver.kql) | medium | persistence, privilege-escalation, T1546.002 | DeviceProcessEvents |
| [Changing Existing Service ImagePath Value Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_service_imagepath_change.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.011 | DeviceProcessEvents |
| [Detected Windows Software Discovery](rules/windows/process_creation/proc_creation_win_reg_software_discovery.kql) | medium | discovery, T1518 | DeviceProcessEvents |
| [Reg Add Suspicious Paths](rules/windows/process_creation/proc_creation_win_reg_susp_paths.kql) | high | persistence, defense-impairment, T1112, T1685 | DeviceProcessEvents |
| [Disabled Volume Snapshots](rules/windows/process_creation/proc_creation_win_reg_volsnap_disable.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Suspicious Windows Defender Registry Key Tampering Via Reg.EXE](rules/windows/process_creation/proc_creation_win_reg_windows_defender_tamper.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Write Protect For Storage Disabled](rules/windows/process_creation/proc_creation_win_reg_write_protect_for_storage_disabled.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension](rules/windows/process_creation/proc_creation_win_regasm_regsvcs_uncommon_extension_execution.kql) | medium | stealth, T1218.009 | DeviceProcessEvents |
| [Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location](rules/windows/process_creation/proc_creation_win_regasm_regsvcs_uncommon_location_execution.kql) | medium | stealth, T1218.009 | DeviceProcessEvents |
| [Exports Critical Registry Keys To a File](rules/windows/process_creation/proc_creation_win_regedit_export_critical_keys.kql) | high | exfiltration, discovery, T1012 | DeviceProcessEvents |
| [Imports Registry Key From a File](rules/windows/process_creation/proc_creation_win_regedit_import_keys.kql) | medium | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Imports Registry Key From an ADS](rules/windows/process_creation/proc_creation_win_regedit_import_keys_ads.kql) | high | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Regedit as Trusted Installer](rules/windows/process_creation/proc_creation_win_regedit_trustedinstaller.kql) | high | privilege-escalation, T1548 | DeviceProcessEvents |
| [Suspicious Registry Modification From ADS Via Regini.EXE](rules/windows/process_creation/proc_creation_win_regini_ads.kql) | high | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [DLL Execution Via Register-cimprovider.exe](rules/windows/process_creation/proc_creation_win_registry_cimprovider_dll_load.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574 | DeviceProcessEvents |
| [Enumeration for 3rd Party Creds From CLI](rules/windows/process_creation/proc_creation_win_registry_enumeration_for_credentials_cli.kql) | medium | credential-access, T1552.002 | DeviceProcessEvents |
| [IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI](rules/windows/process_creation/proc_creation_win_registry_ie_security_zone_protocol_defaults_downgrade.kql) | high | execution, stealth | DeviceProcessEvents |
| [Suspicious Debugger Registration Cmdline](rules/windows/process_creation/proc_creation_win_registry_install_reg_debugger_backdoor.kql) | high | persistence, privilege-escalation, T1546.008 | DeviceProcessEvents |
| [Potential Persistence Via Logon Scripts - CommandLine](rules/windows/process_creation/proc_creation_win_registry_logon_script.kql) | high | privilege-escalation, persistence, T1037.001 | DeviceProcessEvents |
| [Potential Credential Dumping Attempt Using New NetworkProvider - CLI](rules/windows/process_creation/proc_creation_win_registry_new_network_provider.kql) | high | credential-access, T1003 | DeviceProcessEvents |
| [Python Function Execution Security Warning Disabled In Excel](rules/windows/process_creation/proc_creation_win_registry_office_disable_python_security_warnings.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential Privilege Escalation via Service Permissions Weakness](rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.011 | DeviceProcessEvents |
| [Potential Provisioning Registry Key Abuse For Binary Proxy Execution](rules/windows/process_creation/proc_creation_win_registry_provlaunch_provisioning_command.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Potential PowerShell Execution Policy Tampering - ProcCreation](rules/windows/process_creation/proc_creation_win_registry_set_unsecure_powershell_policy.kql) | high | defense-impairment | DeviceProcessEvents |
| [Hiding User Account Via SpecialAccounts Registry Key - CommandLine](rules/windows/process_creation/proc_creation_win_registry_special_accounts_hide_user.kql) | medium | stealth, T1564.002 | DeviceProcessEvents |
| [Persistence Via TypedPaths - CommandLine](rules/windows/process_creation/proc_creation_win_registry_typed_paths_persistence.kql) | medium | persistence | DeviceProcessEvents |
| [Potential Regsvr32 Commandline Flag Anomaly](rules/windows/process_creation/proc_creation_win_regsvr32_flags_anomaly.kql) | medium | stealth, T1218.010 | DeviceProcessEvents |
| [Potentially Suspicious Regsvr32 HTTP IP Pattern](rules/windows/process_creation/proc_creation_win_regsvr32_http_ip_pattern.kql) | high | stealth, T1218.010 | DeviceProcessEvents |
| [Potentially Suspicious Regsvr32 HTTP/FTP Pattern](rules/windows/process_creation/proc_creation_win_regsvr32_network_pattern.kql) | medium | stealth, T1218.010 | DeviceProcessEvents |
| [Suspicious Regsvr32 Execution From Remote Share](rules/windows/process_creation/proc_creation_win_regsvr32_remote_share.kql) | high | stealth, T1218.010 | DeviceProcessEvents |
| [Potentially Suspicious Child Process Of Regsvr32](rules/windows/process_creation/proc_creation_win_regsvr32_susp_child_process.kql) | high | stealth, T1218.010 | DeviceProcessEvents |
| [Regsvr32 Execution From Potential Suspicious Location](rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_1.kql) | medium | stealth, T1218.010 | DeviceProcessEvents |
| [Regsvr32 Execution From Highly Suspicious Location](rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_2.kql) | high | stealth, T1218.010 | DeviceProcessEvents |
| [Regsvr32 DLL Execution With Suspicious File Extension](rules/windows/process_creation/proc_creation_win_regsvr32_susp_extensions.kql) | high | stealth, T1218.010 | DeviceProcessEvents |
| [Scripting/CommandLine Process Spawned Regsvr32](rules/windows/process_creation/proc_creation_win_regsvr32_susp_parent.kql) | medium | stealth, T1218.010 | DeviceProcessEvents |
| [Regsvr32 DLL Execution With Uncommon Extension](rules/windows/process_creation/proc_creation_win_regsvr32_uncommon_extension.kql) | medium | privilege-escalation, persistence, stealth, T1574, execution | DeviceProcessEvents |
| [Remote Access Tool - AnyDesk Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - AnyDesk Piped Password Via CLI](rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_piped_password_via_cli.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate](rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_revoked_cert.kql) | medium | execution, initial-access | DeviceProcessEvents |
| [Remote Access Tool - AnyDesk Silent Installation](rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_silent_install.kql) | high | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - Anydesk Execution From Suspicious Folder](rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.kql) | high | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - GoToAssist Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_gotoopener.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - LogMeIn Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_logmein.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - MeshAgent Command Execution via MeshCentral](rules/windows/process_creation/proc_creation_win_remote_access_tools_meshagent_exec.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - NetSupport Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_netsupport.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - RURAT Execution From Unusual Location](rules/windows/process_creation/proc_creation_win_remote_access_tools_rurat_non_default_location.kql) | medium | stealth | DeviceProcessEvents |
| [Remote Access Tool - ScreenConnect Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - ScreenConnect Installation Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_installation_cli_param.kql) | medium | persistence, initial-access, T1133 | DeviceProcessEvents |
| [Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_remote_execution_susp.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - ScreenConnect Server Web Shell Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_webshell.kql) | high | initial-access, T1190 | DeviceProcessEvents |
| [Remote Access Tool - Simple Help Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_simple_help.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - UltraViewer Execution](rules/windows/process_creation/proc_creation_win_remote_access_tools_ultraviewer.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Renamed AutoHotkey.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_autohotkey.kql) | medium | stealth | DeviceProcessEvents |
| [Potential Defense Evasion Via Binary Rename](rules/windows/process_creation/proc_creation_win_renamed_binary.kql) | medium | stealth, T1036.003 | DeviceProcessEvents |
| [Potential Defense Evasion Via Rename Of Highly Relevant Binaries](rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.kql) | high | stealth, T1036.003 | DeviceProcessEvents |
| [Renamed BOINC Client Execution](rules/windows/process_creation/proc_creation_win_renamed_boinc.kql) | medium | defense-impairment, T1553 | DeviceProcessEvents |
| [Renamed BrowserCore.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_browsercore.kql) | high | credential-access, stealth, T1528, T1036.003 | DeviceProcessEvents |
| [Renamed Cloudflared.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_cloudflared.kql) | high | command-and-control, T1090.001 | DeviceProcessEvents |
| [Renamed CreateDump Utility Execution](rules/windows/process_creation/proc_creation_win_renamed_createdump.kql) | high | stealth, T1036, T1003.001, credential-access | DeviceProcessEvents |
| [Renamed CURL.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_curl.kql) | medium | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Renamed FTP.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_ftp.kql) | medium | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Renamed Gpg.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_gpg4win.kql) | high | impact, T1486 | DeviceProcessEvents |
| [Renamed Jusched.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_jusched.kql) | high | execution, stealth, T1036.003 | DeviceProcessEvents |
| [Renamed Mavinject.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_mavinject.kql) | high | privilege-escalation, stealth, T1055.001, T1218.013 | DeviceProcessEvents |
| [Renamed MegaSync Execution](rules/windows/process_creation/proc_creation_win_renamed_megasync.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Renamed Msdt.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_msdt.kql) | high | stealth, T1036.003 | DeviceProcessEvents |
| [Renamed Microsoft Teams Execution](rules/windows/process_creation/proc_creation_win_renamed_msteams.kql) | medium | stealth | DeviceProcessEvents |
| [Renamed NirCmd.EXE Execution](rules/windows/process_creation/proc_creation_win_renamed_nircmd.kql) | high | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Renamed Office Binary Execution](rules/windows/process_creation/proc_creation_win_renamed_office_processes.kql) | high | stealth, T1036.003 | DeviceProcessEvents |
| [Renamed PingCastle Binary Execution](rules/windows/process_creation/proc_creation_win_renamed_pingcastle.kql) | high | execution, stealth, T1059, T1202 | DeviceProcessEvents |
| [Renamed Plink Execution](rules/windows/process_creation/proc_creation_win_renamed_plink.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Visual Studio NodejsTools PressAnyKey Renamed Execution](rules/windows/process_creation/proc_creation_win_renamed_pressanykey.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Potential Renamed Rundll32 Execution](rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.kql) | high | execution | DeviceProcessEvents |
| [Renamed Remote Utilities RAT (RURAT) Execution](rules/windows/process_creation/proc_creation_win_renamed_rurat.kql) | medium | collection, command-and-control, discovery, stealth, S0592 | DeviceProcessEvents |
| [Renamed SysInternals DebugView Execution](rules/windows/process_creation/proc_creation_win_renamed_sysinternals_debugview.kql) | high | resource-development, T1588.002 | DeviceProcessEvents |
| [Renamed ProcDump Execution](rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.kql) | high | stealth, T1036.003 | DeviceProcessEvents |
| [Renamed PsExec Service Execution](rules/windows/process_creation/proc_creation_win_renamed_sysinternals_psexec_service.kql) | high | execution | DeviceProcessEvents |
| [Renamed Sysinternals Sdelete Execution](rules/windows/process_creation/proc_creation_win_renamed_sysinternals_sdelete.kql) | high | impact, T1485 | DeviceProcessEvents |
| [Renamed Vmnat.exe Execution](rules/windows/process_creation/proc_creation_win_renamed_vmnat.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Renamed Whoami Execution](rules/windows/process_creation/proc_creation_win_renamed_whoami.kql) | critical | discovery, T1033 | DeviceProcessEvents |
| [Capture Credentials with Rpcping.exe](rules/windows/process_creation/proc_creation_win_rpcping_credential_capture.kql) | medium | credential-access, T1003 | DeviceProcessEvents |
| [Ruby Inline Command Execution](rules/windows/process_creation/proc_creation_win_ruby_inline_command_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Potential Rundll32 Execution With DLL Stored In ADS](rules/windows/process_creation/proc_creation_win_rundll32_ads_stored_dll_execution.kql) | high | stealth, T1564.004 | DeviceProcessEvents |
| [Suspicious Advpack Call Via Rundll32.EXE](rules/windows/process_creation/proc_creation_win_rundll32_advpack_obfuscated_ordinal_call.kql) | high | stealth | DeviceProcessEvents |
| [Suspicious Rundll32 Invoking Inline VBScript](rules/windows/process_creation/proc_creation_win_rundll32_inline_vbs.kql) | high | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [Rundll32 InstallScreenSaver Execution](rules/windows/process_creation/proc_creation_win_rundll32_installscreensaver.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Suspicious Key Manager Access](rules/windows/process_creation/proc_creation_win_rundll32_keymgr.kql) | high | credential-access, T1555.004 | DeviceProcessEvents |
| [Mshtml.DLL RunHTMLApplication Suspicious Usage](rules/windows/process_creation/proc_creation_win_rundll32_mshtml_runhtmlapplication.kql) | high | execution, stealth | DeviceProcessEvents |
| [Rundll32 Execution Without CommandLine Parameters](rules/windows/process_creation/proc_creation_win_rundll32_no_params.kql) | high | stealth, T1202 | DeviceProcessEvents |
| [Suspicious NTLM Authentication on the Printer Spooler Service](rules/windows/process_creation/proc_creation_win_rundll32_ntlmrelay.kql) | high | privilege-escalation, credential-access, T1212 | DeviceProcessEvents |
| [Potential Obfuscated Ordinal Call Via Rundll32](rules/windows/process_creation/proc_creation_win_rundll32_obfuscated_ordinal_call.kql) | medium | stealth, T1027.010 | DeviceProcessEvents |
| [Rundll32 Spawned Via Explorer.EXE](rules/windows/process_creation/proc_creation_win_rundll32_parent_explorer.kql) | medium | stealth | DeviceProcessEvents |
| [Process Memory Dump Via Comsvcs.DLL](rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.kql) | high | credential-access, stealth, T1036, T1003.001 | DeviceProcessEvents |
| [Rundll32 Registered COM Objects](rules/windows/process_creation/proc_creation_win_rundll32_registered_com_objects.kql) | high | privilege-escalation, persistence, T1546.015 | DeviceProcessEvents |
| [Suspicious Process Start Locations](rules/windows/process_creation/proc_creation_win_rundll32_run_locations.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [Suspicious Rundll32 Setupapi.dll Activity](rules/windows/process_creation/proc_creation_win_rundll32_setupapi_installhinfsection.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Shell32 DLL Execution in Suspicious Directory](rules/windows/process_creation/proc_creation_win_rundll32_shell32_susp_execution.kql) | high | execution, stealth, T1218.011 | DeviceProcessEvents |
| [Potential ShellDispatch.DLL Functionality Abuse](rules/windows/process_creation/proc_creation_win_rundll32_shelldispatch_potential_abuse.kql) | medium | execution, stealth | DeviceProcessEvents |
| [RunDLL32 Spawning Explorer](rules/windows/process_creation/proc_creation_win_rundll32_spawn_explorer.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Potentially Suspicious Rundll32 Activity](rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Suspicious Control Panel DLL Load](rules/windows/process_creation/proc_creation_win_rundll32_susp_control_dll_load.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Suspicious Rundll32 Execution With Image Extension](rules/windows/process_creation/proc_creation_win_rundll32_susp_execution_with_image_extension.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Suspicious Usage Of ShellExec_RunDLL](rules/windows/process_creation/proc_creation_win_rundll32_susp_shellexec_execution.kql) | high | stealth | DeviceProcessEvents |
| [Suspicious ShellExec_RunDLL Call Via Ordinal](rules/windows/process_creation/proc_creation_win_rundll32_susp_shellexec_ordinal_execution.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [ShimCache Flush](rules/windows/process_creation/proc_creation_win_rundll32_susp_shimcache_flush.kql) | high | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Suspicious Rundll32 Activity Invoking Sys File](rules/windows/process_creation/proc_creation_win_rundll32_sys.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Potentially Suspicious Rundll32.EXE Execution of UDL File](rules/windows/process_creation/proc_creation_win_rundll32_udl_exec.kql) | medium | execution, command-and-control, stealth, T1218.011, T1071 | DeviceProcessEvents |
| [Rundll32 UNC Path Execution](rules/windows/process_creation/proc_creation_win_rundll32_unc_path.kql) | high | execution, lateral-movement, stealth, T1021.002, T1218.011 | DeviceProcessEvents |
| [Rundll32 Execution With Uncommon DLL Extension](rules/windows/process_creation/proc_creation_win_rundll32_uncommon_dll_extension.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Suspicious Workstation Locking via Rundll32](rules/windows/process_creation/proc_creation_win_rundll32_user32_dll.kql) | medium | stealth | DeviceProcessEvents |
| [WebDav Client Execution Via Rundll32.EXE](rules/windows/process_creation/proc_creation_win_rundll32_webdav_client_execution.kql) | medium | exfiltration, T1048.003 | DeviceProcessEvents |
| [Suspicious WebDav Client Execution Via Rundll32.EXE](rules/windows/process_creation/proc_creation_win_rundll32_webdav_client_susp_execution.kql) | high | exfiltration, T1048.003 | DeviceProcessEvents |
| [Rundll32 Execution Without Parameters](rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.kql) | high | lateral-movement, T1021.002, T1570, execution, T1569.002 | DeviceProcessEvents |
| [Possible Privilege Escalation via Weak Service Permissions](rules/windows/process_creation/proc_creation_win_sc_change_sevice_image_path_by_non_admin.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.011 | DeviceProcessEvents |
| [Service StartupType Change Via Sc.EXE](rules/windows/process_creation/proc_creation_win_sc_disable_service.kql) | medium | execution, defense-impairment, T1685 | DeviceProcessEvents |
| [New Kernel Driver Via SC.EXE](rules/windows/process_creation/proc_creation_win_sc_new_kernel_driver.kql) | medium | persistence, privilege-escalation, T1543.003 | DeviceProcessEvents |
| [Allow Service Access Using Security Descriptor Tampering Via Sc.EXE](rules/windows/process_creation/proc_creation_win_sc_sdset_allow_service_changes.kql) | high | privilege-escalation, persistence, T1543.003 | DeviceProcessEvents |
| [Deny Service Access Using Security Descriptor Tampering Via Sc.EXE](rules/windows/process_creation/proc_creation_win_sc_sdset_deny_service_access.kql) | high | privilege-escalation, persistence, T1543.003 | DeviceProcessEvents |
| [Service DACL Abuse To Hide Services Via Sc.EXE](rules/windows/process_creation/proc_creation_win_sc_sdset_hide_sevices.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.011 | DeviceProcessEvents |
| [Service Security Descriptor Tampering Via Sc.EXE](rules/windows/process_creation/proc_creation_win_sc_sdset_modification.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.011 | DeviceProcessEvents |
| [Suspicious Service Path Modification](rules/windows/process_creation/proc_creation_win_sc_service_path_modification.kql) | high | persistence, privilege-escalation, T1543.003 | DeviceProcessEvents |
| [Potential Persistence Attempt Via Existing Service Tampering](rules/windows/process_creation/proc_creation_win_sc_service_tamper_for_persistence.kql) | medium | privilege-escalation, persistence, execution, stealth, T1543.003, T1574.011 | DeviceProcessEvents |
| [Suspicious Schtasks Execution AppData Folder](rules/windows/process_creation/proc_creation_win_schtasks_appdata_local_system.kql) | high | privilege-escalation, execution, persistence, T1053.005, T1059.001 | DeviceProcessEvents |
| [Suspicious Modification Of Scheduled Tasks](rules/windows/process_creation/proc_creation_win_schtasks_change.kql) | high | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Suspicious Scheduled Task Creation Involving Temp Folder](rules/windows/process_creation/proc_creation_win_schtasks_creation_temp_folder.kql) | high | privilege-escalation, execution, persistence, T1053.005 | DeviceProcessEvents |
| [Delete Important Scheduled Task](rules/windows/process_creation/proc_creation_win_schtasks_delete.kql) | high | impact, T1489 | DeviceProcessEvents |
| [Delete All Scheduled Tasks](rules/windows/process_creation/proc_creation_win_schtasks_delete_all.kql) | high | impact, T1489 | DeviceProcessEvents |
| [Disable Important Scheduled Task](rules/windows/process_creation/proc_creation_win_schtasks_disable.kql) | high | impact, T1489 | DeviceProcessEvents |
| [Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE](rules/windows/process_creation/proc_creation_win_schtasks_env_folder.kql) | medium | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Schtasks From Suspicious Folders](rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.kql) | high | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Suspicious Scheduled Task Name As GUID](rules/windows/process_creation/proc_creation_win_schtasks_guid_task_name.kql) | medium | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Uncommon One Time Only Scheduled Task At 00:00](rules/windows/process_creation/proc_creation_win_schtasks_one_time_only_midnight_task.kql) | high | execution, persistence, privilege-escalation, T1053.005 | DeviceProcessEvents |
| [Potential Persistence Via Microsoft Compatibility Appraiser](rules/windows/process_creation/proc_creation_win_schtasks_persistence_windows_telemetry.kql) | medium | privilege-escalation, execution, persistence, T1053.005 | DeviceProcessEvents |
| [Potential Persistence Via Powershell Search Order Hijacking - Task](rules/windows/process_creation/proc_creation_win_schtasks_powershell_persistence.kql) | high | privilege-escalation, execution, persistence, T1053.005, T1059.001 | DeviceProcessEvents |
| [Scheduled Task Executing Payload from Registry](rules/windows/process_creation/proc_creation_win_schtasks_reg_loader.kql) | medium | privilege-escalation, execution, persistence, T1053.005, T1059.001 | DeviceProcessEvents |
| [Scheduled Task Executing Encoded Payload from Registry](rules/windows/process_creation/proc_creation_win_schtasks_reg_loader_encoded.kql) | high | privilege-escalation, execution, persistence, T1053.005, T1059.001 | DeviceProcessEvents |
| [Suspicious Schtasks Schedule Types](rules/windows/process_creation/proc_creation_win_schtasks_schedule_type.kql) | high | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Suspicious Schtasks Schedule Type With High Privileges](rules/windows/process_creation/proc_creation_win_schtasks_schedule_type_system.kql) | medium | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Suspicious Scheduled Task Creation via Masqueraded XML File](rules/windows/process_creation/proc_creation_win_schtasks_schedule_via_masqueraded_xml_file.kql) | medium | privilege-escalation, execution, persistence, stealth, T1036.005, T1053.005 | DeviceProcessEvents |
| [Suspicious Command Patterns In Scheduled Task Creation](rules/windows/process_creation/proc_creation_win_schtasks_susp_pattern.kql) | high | privilege-escalation, persistence, execution, T1053.005 | DeviceProcessEvents |
| [Schtasks Creation Or Modification With SYSTEM Privileges](rules/windows/process_creation/proc_creation_win_schtasks_system.kql) | high | privilege-escalation, execution, persistence, T1053.005 | DeviceProcessEvents |
| [Script Event Consumer Spawning Process](rules/windows/process_creation/proc_creation_win_scrcons_susp_child_process.kql) | high | execution, T1047 | DeviceProcessEvents |
| [Potential Shim Database Persistence via Sdbinst.EXE](rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.kql) | medium | persistence, privilege-escalation, T1546.011 | DeviceProcessEvents |
| [Uncommon Extension Shim Database Installation Via Sdbinst.EXE](rules/windows/process_creation/proc_creation_win_sdbinst_susp_extension.kql) | medium | persistence, privilege-escalation, T1546.011 | DeviceProcessEvents |
| [Sdclt Child Processes](rules/windows/process_creation/proc_creation_win_sdclt_child_process.kql) | medium | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Sdiagnhost Calling Suspicious Child Process](rules/windows/process_creation/proc_creation_win_sdiagnhost_susp_child.kql) | high | stealth, T1036, T1218 | DeviceProcessEvents |
| [Potential Suspicious Activity Using SeCEdit](rules/windows/process_creation/proc_creation_win_secedit_execution.kql) | medium | collection, discovery, persistence, credential-access, privilege-escalation, execution, stealth, defense-impairment, T1685.001, T1547.001, T1505.005, T1556.002, T1685, T1574.007, T1564.002, T1546.008, T1546.007, T1547.014, T1547.010, T1547.002, T1557, T1082 | DeviceProcessEvents |
| [Suspicious Serv-U Process Pattern](rules/windows/process_creation/proc_creation_win_servu_susp_child_process.kql) | high | credential-access, T1555 | DeviceProcessEvents |
| [Uncommon Child Process Of Setres.EXE](rules/windows/process_creation/proc_creation_win_setres_uncommon_child_process.kql) | high | stealth, T1218, T1202 | DeviceProcessEvents |
| [Potential SPN Enumeration Via Setspn.EXE](rules/windows/process_creation/proc_creation_win_setspn_spn_enumeration.kql) | medium | credential-access, T1558.003 | DeviceProcessEvents |
| [Setup16.EXE Execution With Custom .Lst File](rules/windows/process_creation/proc_creation_win_setup16_custom_lst_execution.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574.005 | DeviceProcessEvents |
| [Suspicious Execution of Shutdown](rules/windows/process_creation/proc_creation_win_shutdown_execution.kql) | medium | impact, T1529 | DeviceProcessEvents |
| [Suspicious Execution of Shutdown to Log Out](rules/windows/process_creation/proc_creation_win_shutdown_logoff.kql) | medium | impact, T1529 | DeviceProcessEvents |
| [Uncommon Sigverif.EXE Child Process](rules/windows/process_creation/proc_creation_win_sigverif_uncommon_child_process.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [Uncommon Child Processes Of SndVol.exe](rules/windows/process_creation/proc_creation_win_sndvol_susp_child_processes.kql) | medium | execution | DeviceProcessEvents |
| [Audio Capture via SoundRecorder](rules/windows/process_creation/proc_creation_win_soundrecorder_audio_capture.kql) | medium | collection, T1123 | DeviceProcessEvents |
| [Suspicious Splwow64 Without Params](rules/windows/process_creation/proc_creation_win_splwow64_cli_anomaly.kql) | high | stealth, T1202 | DeviceProcessEvents |
| [Suspicious Spool Service Child Process](rules/windows/process_creation/proc_creation_win_spoolsv_susp_child_processes.kql) | high | execution, T1203, privilege-escalation, T1068 | DeviceProcessEvents |
| [Veeam Backup Database Suspicious Query](rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_db_recon.kql) | medium | collection, T1005 | DeviceProcessEvents |
| [VeeamBackup Database Credentials Dump Via Sqlcmd.EXE](rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_dump.kql) | high | collection, T1005 | DeviceProcessEvents |
| [SQLite Chromium Profile Data DB Access](rules/windows/process_creation/proc_creation_win_sqlite_chromium_profile_data.kql) | high | credential-access, T1539, T1555.003, collection, T1005 | DeviceProcessEvents |
| [SQLite Firefox Profile Data DB Access](rules/windows/process_creation/proc_creation_win_sqlite_firefox_gecko_profile_data.kql) | high | credential-access, T1539, collection, T1005 | DeviceProcessEvents |
| [Arbitrary File Download Via Squirrel.EXE](rules/windows/process_creation/proc_creation_win_squirrel_download.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Process Proxy Execution Via Squirrel.EXE](rules/windows/process_creation/proc_creation_win_squirrel_proxy_execution.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Port Forwarding Activity Via SSH.EXE](rules/windows/process_creation/proc_creation_win_ssh_port_forward.kql) | medium | command-and-control, lateral-movement, T1572, T1021.001, T1021.004 | DeviceProcessEvents |
| [Potential RDP Tunneling Via SSH](rules/windows/process_creation/proc_creation_win_ssh_rdp_tunneling.kql) | high | command-and-control, T1572 | DeviceProcessEvents |
| [Potential Amazon SSM Agent Hijacking](rules/windows/process_creation/proc_creation_win_ssm_agent_abuse.kql) | medium | command-and-control, persistence, T1219.002 | DeviceProcessEvents |
| [Execution via stordiag.exe](rules/windows/process_creation/proc_creation_win_stordiag_susp_child_process.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Start of NT Virtual DOS Machine](rules/windows/process_creation/proc_creation_win_susp_16bit_application.kql) | medium | stealth | DeviceProcessEvents |
| [Abused Debug Privilege by Arbitrary Parent Processes](rules/windows/process_creation/proc_creation_win_susp_abusing_debug_privilege.kql) | high | privilege-escalation, T1548 | DeviceProcessEvents |
| [User Added to Local Administrators Group](rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.kql) | medium | privilege-escalation, persistence, T1098 | DeviceProcessEvents |
| [User Added To Highly Privileged Group](rules/windows/process_creation/proc_creation_win_susp_add_user_privileged_group.kql) | high | privilege-escalation, persistence, T1098 | DeviceProcessEvents |
| [User Added to Remote Desktop Users Group](rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop_group.kql) | high | initial-access, persistence, lateral-movement, T1133, T1136.001, T1021.001 | DeviceProcessEvents |
| [Execute From Alternate Data Streams](rules/windows/process_creation/proc_creation_win_susp_alternate_data_streams.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Always Install Elevated Windows Installer](rules/windows/process_creation/proc_creation_win_susp_always_install_elevated_windows_installer.kql) | medium | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Potentially Suspicious Windows App Activity](rules/windows/process_creation/proc_creation_win_susp_appx_execution.kql) | medium | stealth | DeviceProcessEvents |
| [Arbitrary Shell Command Execution Via Settingcontent-Ms](rules/windows/process_creation/proc_creation_win_susp_arbitrary_shell_execution_via_settingcontent.kql) | medium | T1204, T1566.001, execution, initial-access | DeviceProcessEvents |
| [Phishing Pattern ISO in Archive](rules/windows/process_creation/proc_creation_win_susp_archiver_iso_phishing.kql) | high | initial-access, T1566 | DeviceProcessEvents |
| [Automated Collection Command Prompt](rules/windows/process_creation/proc_creation_win_susp_automated_collection.kql) | medium | collection, T1119, credential-access, T1552.001 | DeviceProcessEvents |
| [Bad Opsec Defaults Sacrificial Processes With Improper Arguments](rules/windows/process_creation/proc_creation_win_susp_bad_opsec_sacrificial_processes.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Potential Suspicious Browser Launch From Document Reader Process](rules/windows/process_creation/proc_creation_win_susp_browser_launch_from_document_reader_process.kql) | medium | execution, T1204.002 | DeviceProcessEvents |
| [Suspicious Child Process Created as System](rules/windows/process_creation/proc_creation_win_susp_child_process_as_system_.kql) | high | privilege-escalation, stealth, T1134.002 | DeviceProcessEvents |
| [Potential Commandline Obfuscation Using Escape Characters](rules/windows/process_creation/proc_creation_win_susp_cli_obfuscation_escape_char.kql) | medium | stealth, T1140 | DeviceProcessEvents |
| [Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image](rules/windows/process_creation/proc_creation_win_susp_cli_obfuscation_unicode_img.kql) | high | stealth, T1027 | DeviceProcessEvents |
| [Potential Command Line Path Traversal Evasion Attempt](rules/windows/process_creation/proc_creation_win_susp_commandline_path_traversal_evasion.kql) | medium | stealth, T1036 | DeviceProcessEvents |
| [Potential Browser Data Stealing](rules/windows/process_creation/proc_creation_win_susp_copy_browser_data.kql) | medium | credential-access, T1555.003 | DeviceProcessEvents |
| [Copy From Or To Admin Share Or Sysvol Folder](rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.kql) | medium | lateral-movement, collection, exfiltration, T1039, T1048, T1021.002 | DeviceProcessEvents |
| [Suspicious Copy From or To System Directory](rules/windows/process_creation/proc_creation_win_susp_copy_system_dir.kql) | medium | stealth, T1036.003 | DeviceProcessEvents |
| [LOL-Binary Copied From System Directory](rules/windows/process_creation/proc_creation_win_susp_copy_system_dir_lolbin.kql) | high | stealth, T1036.003 | DeviceProcessEvents |
| [Potential Crypto Mining Activity](rules/windows/process_creation/proc_creation_win_susp_crypto_mining_monero.kql) | high | impact, T1496 | DeviceProcessEvents |
| [Potential Data Exfiltration Activity Via CommandLine Tools](rules/windows/process_creation/proc_creation_win_susp_data_exfiltration_via_cli.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Raccine Uninstall](rules/windows/process_creation/proc_creation_win_susp_disable_raccine.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Suspicious Double Extension File Execution](rules/windows/process_creation/proc_creation_win_susp_double_extension.kql) | high | initial-access, T1566.001 | DeviceProcessEvents |
| [Suspicious Parent Double Extension File Execution](rules/windows/process_creation/proc_creation_win_susp_double_extension_parent.kql) | high | stealth, T1036.007 | DeviceProcessEvents |
| [Suspicious Download from Office Domain](rules/windows/process_creation/proc_creation_win_susp_download_office_domain.kql) | high | command-and-control, resource-development, T1105, T1608 | DeviceProcessEvents |
| [DumpStack.log Defender Evasion](rules/windows/process_creation/proc_creation_win_susp_dumpstack_log_evasion.kql) | critical | defense-impairment | DeviceProcessEvents |
| [Always Install Elevated MSI Spawned Cmd And Powershell](rules/windows/process_creation/proc_creation_win_susp_elavated_msi_spawned_shell.kql) | medium | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Suspicious Electron Application Child Processes](rules/windows/process_creation/proc_creation_win_susp_electron_app_children.kql) | medium | execution | DeviceProcessEvents |
| [Potentially Suspicious Electron Application CommandLine](rules/windows/process_creation/proc_creation_win_susp_electron_execution_proxy.kql) | medium | execution | DeviceProcessEvents |
| [Hidden Powershell in Link File Pattern](rules/windows/process_creation/proc_creation_win_susp_embed_exe_lnk.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1](rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_1.kql) | high | stealth | DeviceProcessEvents |
| [Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2](rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_2.kql) | high | stealth | DeviceProcessEvents |
| [Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3](rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_3.kql) | high | stealth | DeviceProcessEvents |
| [Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4](rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_4.kql) | high | stealth | DeviceProcessEvents |
| [ETW Logging Tamper In .NET Processes Via CommandLine](rules/windows/process_creation/proc_creation_win_susp_etw_modification_cmdline.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [ETW Trace Evasion Activity](rules/windows/process_creation/proc_creation_win_susp_etw_trace_evasion.kql) | high | stealth, defense-impairment, T1070, T1685 | DeviceProcessEvents |
| [Suspicious Eventlog Clearing or Configuration Change Activity](rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.kql) | high | defense-impairment, T1685.005, T1685.001 | DeviceProcessEvents |
| [Potentially Suspicious EventLog Recon Activity Using Log Query Utilities](rules/windows/process_creation/proc_creation_win_susp_eventlog_content_recon.kql) | medium | credential-access, discovery, T1552, T1087 | DeviceProcessEvents |
| [Potentially Suspicious Execution From Parent Process In Public Folder](rules/windows/process_creation/proc_creation_win_susp_execution_from_public_folder_as_parent.kql) | high | execution, stealth, T1564, T1059 | DeviceProcessEvents |
| [Process Execution From A Potentially Suspicious Folder](rules/windows/process_creation/proc_creation_win_susp_execution_path.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Suspicious File Characteristics Due to Missing Fields](rules/windows/process_creation/proc_creation_win_susp_file_characteristics.kql) | medium | execution, T1059.006 | DeviceProcessEvents |
| [Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS](rules/windows/process_creation/proc_creation_win_susp_gather_network_info_execution.kql) | high | discovery, execution, T1615, T1059.005 | DeviceProcessEvents |
| [Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream - CLI](rules/windows/process_creation/proc_creation_win_susp_hidden_dir_index_allocation.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Writing Of Malicious Files To The Fonts Folder](rules/windows/process_creation/proc_creation_win_susp_hiding_malware_in_fonts_folder.kql) | medium | stealth, T1211, T1059, persistence, execution | DeviceProcessEvents |
| [Potential Homoglyph Attack Using Lookalike Characters](rules/windows/process_creation/proc_creation_win_susp_homoglyph_cyrillic_lookalikes.kql) | medium | stealth, T1036, T1036.003 | DeviceProcessEvents |
| [Execution Of Non-Existing File](rules/windows/process_creation/proc_creation_win_susp_image_missing.kql) | high | stealth, privilege-escalation, T1055 | DeviceProcessEvents |
| [Base64 MZ Header In CommandLine](rules/windows/process_creation/proc_creation_win_susp_inline_base64_mz_header.kql) | high | execution | DeviceProcessEvents |
| [Potential WinAPI Calls Via CommandLine](rules/windows/process_creation/proc_creation_win_susp_inline_win_api_access.kql) | high | execution, T1106 | DeviceProcessEvents |
| [Potentially Suspicious JWT Token Search Via CLI](rules/windows/process_creation/proc_creation_win_susp_jwt_token_search.kql) | medium | credential-access, T1528, T1552.001 | DeviceProcessEvents |
| [LSASS Dump Keyword In CommandLine](rules/windows/process_creation/proc_creation_win_susp_lsass_dmp_cli_keywords.kql) | high | credential-access, T1003.001 | DeviceProcessEvents |
| [Potential File Download Via MS-AppInstaller Protocol Handler](rules/windows/process_creation/proc_creation_win_susp_ms_appinstaller_download.kql) | medium | execution, stealth, T1218 | DeviceProcessEvents |
| [Suspicious Scan Loop Network](rules/windows/process_creation/proc_creation_win_susp_network_scan_loop.kql) | medium | execution, T1059, discovery, T1018 | DeviceProcessEvents |
| [Potential Network Sniffing Activity Using Network Tools](rules/windows/process_creation/proc_creation_win_susp_network_sniffing.kql) | medium | credential-access, discovery, T1040 | DeviceProcessEvents |
| [Process Launched Without Image Name](rules/windows/process_creation/proc_creation_win_susp_no_image_name.kql) | medium | stealth | DeviceProcessEvents |
| [Execution of Suspicious File Type Extension](rules/windows/process_creation/proc_creation_win_susp_non_exe_image.kql) | medium | stealth | DeviceProcessEvents |
| [Non-privileged Usage of Reg or Powershell](rules/windows/process_creation/proc_creation_win_susp_non_priv_reg_or_ps.kql) | high | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Suspicious Process Patterns NTDS.DIT Exfil](rules/windows/process_creation/proc_creation_win_susp_ntds.kql) | high | credential-access, T1003.003 | DeviceProcessEvents |
| [Potentially Suspicious Call To Win32_NTEventlogFile Class](rules/windows/process_creation/proc_creation_win_susp_nteventlogfile_usage.kql) | high | defense-impairment | DeviceProcessEvents |
| [Use Short Name Path in Image](rules/windows/process_creation/proc_creation_win_susp_ntfs_short_name_path_use_image.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Use NTFS Short Name in Command Line](rules/windows/process_creation/proc_creation_win_susp_ntfs_short_name_use_cli.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Use NTFS Short Name in Image](rules/windows/process_creation/proc_creation_win_susp_ntfs_short_name_use_image.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Obfuscated IP Download Activity](rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_download.kql) | medium | discovery | DeviceProcessEvents |
| [Obfuscated IP Via CLI](rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_via_cli.kql) | medium | discovery | DeviceProcessEvents |
| [Suspicious Process Parents](rules/windows/process_creation/proc_creation_win_susp_parents.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Potential PowerShell Execution Via DLL](rules/windows/process_creation/proc_creation_win_susp_powershell_execution_via_dll.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Privilege Escalation via Named Pipe Impersonation](rules/windows/process_creation/proc_creation_win_susp_priv_escalation_via_named_pipe.kql) | high | lateral-movement, T1021 | DeviceProcessEvents |
| [Private Keys Reconnaissance Via CommandLine Tools](rules/windows/process_creation/proc_creation_win_susp_private_keys_recon.kql) | medium | credential-access, T1552.004 | DeviceProcessEvents |
| [Suspicious RunAs-Like Flag Combination](rules/windows/process_creation/proc_creation_win_susp_privilege_escalation_cli_patterns.kql) | medium | privilege-escalation | DeviceProcessEvents |
| [Suspicious Program Names](rules/windows/process_creation/proc_creation_win_susp_progname.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Recon Information for Export with Command Prompt](rules/windows/process_creation/proc_creation_win_susp_recon.kql) | medium | collection, T1119 | DeviceProcessEvents |
| [Suspicious Process Execution From Fake Recycle.Bin Folder](rules/windows/process_creation/proc_creation_win_susp_recycle_bin_fake_execution.kql) | high | persistence, stealth | DeviceProcessEvents |
| [Suspicious Redirection to Local Admin Share](rules/windows/process_creation/proc_creation_win_susp_redirect_local_admin_share.kql) | high | exfiltration, T1048 | DeviceProcessEvents |
| [Registry Modification of MS-settings Protocol Handler](rules/windows/process_creation/proc_creation_win_susp_registry_modification_of_ms_setting_protocol_handler.kql) | medium | privilege-escalation, persistence, defense-impairment, T1548.002, T1546.001, T1112 | DeviceProcessEvents |
| [Potential Remote Desktop Tunneling](rules/windows/process_creation/proc_creation_win_susp_remote_desktop_tunneling.kql) | medium | lateral-movement, T1021 | DeviceProcessEvents |
| [Potential Defense Evasion Via Right-to-Left Override](rules/windows/process_creation/proc_creation_win_susp_right_to_left_override.kql) | high | stealth, T1036.002 | DeviceProcessEvents |
| [Script Interpreter Execution From Suspicious Folder](rules/windows/process_creation/proc_creation_win_susp_script_exec_from_env_folder.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Sensitive File Access Via Volume Shadow Copy Backup](rules/windows/process_creation/proc_creation_win_susp_sensitive_file_access_shadowcopy.kql) | high | impact, T1490 | DeviceProcessEvents |
| [Suspicious New Service Creation](rules/windows/process_creation/proc_creation_win_susp_service_creation.kql) | high | persistence, privilege-escalation, T1543.003 | DeviceProcessEvents |
| [Suspicious Service Binary Directory](rules/windows/process_creation/proc_creation_win_susp_service_dir.kql) | high | stealth, T1202 | DeviceProcessEvents |
| [Suspicious Windows Service Tampering](rules/windows/process_creation/proc_creation_win_susp_service_tamper.kql) | high | impact, defense-impairment, T1489, T1685 | DeviceProcessEvents |
| [Shadow Copies Creation Using Operating Systems Utilities](rules/windows/process_creation/proc_creation_win_susp_shadow_copies_creation.kql) | medium | credential-access, T1003, T1003.002, T1003.003 | DeviceProcessEvents |
| [Shadow Copies Deletion Using Operating Systems Utilities](rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.kql) | high | impact, stealth, T1070, T1490 | DeviceProcessEvents |
| [Process Creation Using Sysnative Folder](rules/windows/process_creation/proc_creation_win_susp_sysnative.kql) | medium | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [System File Execution Location Anomaly](rules/windows/process_creation/proc_creation_win_susp_system_exe_anomaly.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Suspicious SYSTEM User Process Creation](rules/windows/process_creation/proc_creation_win_susp_system_user_anomaly.kql) | high | credential-access, privilege-escalation, stealth, T1134, T1003, T1027 | DeviceProcessEvents |
| [Suspicious SYSVOL Domain Group Policy Access](rules/windows/process_creation/proc_creation_win_susp_sysvol_access.kql) | medium | credential-access, T1552.006 | DeviceProcessEvents |
| [Tasks Folder Evasion](rules/windows/process_creation/proc_creation_win_susp_task_folder_evasion.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Malicious PE Execution by Microsoft Visual Studio Debugger](rules/windows/process_creation/proc_creation_win_susp_use_of_vsjitdebugger_bin.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious Userinit Child Process](rules/windows/process_creation/proc_creation_win_susp_userinit_child.kql) | medium | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [Weak or Abused Passwords In CLI](rules/windows/process_creation/proc_creation_win_susp_weak_or_abused_passwords.kql) | medium | execution, stealth | DeviceProcessEvents |
| [Usage Of Web Request Commands And Cmdlets](rules/windows/process_creation/proc_creation_win_susp_web_request_cmd_and_cmdlets.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [WhoAmI as Parameter](rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.kql) | high | discovery, T1033 | DeviceProcessEvents |
| [Execution via WorkFolders.exe](rules/windows/process_creation/proc_creation_win_susp_workfolders.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [Suspect Svchost Activity](rules/windows/process_creation/proc_creation_win_svchost_execution_with_no_cli_flags.kql) | high | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [Suspicious Process Masquerading As SvcHost.EXE](rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.kql) | high | stealth, T1036.005 | DeviceProcessEvents |
| [Terminal Service Process Spawn](rules/windows/process_creation/proc_creation_win_svchost_termserv_proc_spawn.kql) | high | initial-access, T1190, lateral-movement, T1210 | DeviceProcessEvents |
| [Uncommon Svchost Parent Process](rules/windows/process_creation/proc_creation_win_svchost_uncommon_parent_process.kql) | medium | stealth, T1036.005 | DeviceProcessEvents |
| [Permission Check Via Accesschk.EXE](rules/windows/process_creation/proc_creation_win_sysinternals_accesschk_check_permissions.kql) | medium | discovery, T1069.001 | DeviceProcessEvents |
| [Active Directory Database Snapshot Via ADExplorer](rules/windows/process_creation/proc_creation_win_sysinternals_adexplorer_execution.kql) | medium | discovery, T1087.002, T1069.002, T1482 | DeviceProcessEvents |
| [Suspicious Active Directory Database Snapshot Via ADExplorer](rules/windows/process_creation/proc_creation_win_sysinternals_adexplorer_susp_execution.kql) | high | discovery, T1087.002, T1069.002, T1482 | DeviceProcessEvents |
| [Potential Memory Dumping Activity Via LiveKD](rules/windows/process_creation/proc_creation_win_sysinternals_livekd_execution.kql) | medium | stealth | DeviceProcessEvents |
| [Kernel Memory Dump Via LiveKD](rules/windows/process_creation/proc_creation_win_sysinternals_livekd_kernel_memory_dump.kql) | high | stealth | DeviceProcessEvents |
| [Procdump Execution](rules/windows/process_creation/proc_creation_win_sysinternals_procdump.kql) | medium | stealth, T1036, T1003.001, credential-access | DeviceProcessEvents |
| [Potential SysInternals ProcDump Evasion](rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.kql) | high | stealth, T1036, T1003.001, credential-access | DeviceProcessEvents |
| [Potential LSASS Process Dump Via Procdump](rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.kql) | high | stealth, T1036, credential-access, T1003.001 | DeviceProcessEvents |
| [Psexec Execution](rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution.kql) | medium | execution, lateral-movement, T1569, T1021 | DeviceProcessEvents |
| [PsExec/PAExec Escalation to LOCAL SYSTEM](rules/windows/process_creation/proc_creation_win_sysinternals_psexec_paexec_escalate_system.kql) | high | resource-development, T1587.001 | DeviceProcessEvents |
| [Potential PsExec Remote Execution](rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote_execution.kql) | high | resource-development, T1587.001 | DeviceProcessEvents |
| [PsExec Service Execution](rules/windows/process_creation/proc_creation_win_sysinternals_psexesvc.kql) | medium | execution | DeviceProcessEvents |
| [PsExec Service Child Process Execution as LOCAL SYSTEM](rules/windows/process_creation/proc_creation_win_sysinternals_psexesvc_as_system.kql) | high | execution | DeviceProcessEvents |
| [Suspicious Use of PsLogList](rules/windows/process_creation/proc_creation_win_sysinternals_psloglist.kql) | medium | discovery, T1087, T1087.001, T1087.002 | DeviceProcessEvents |
| [Sysinternals PsService Execution](rules/windows/process_creation/proc_creation_win_sysinternals_psservice.kql) | medium | privilege-escalation, discovery, persistence, T1543.003 | DeviceProcessEvents |
| [Sysinternals PsSuspend Execution](rules/windows/process_creation/proc_creation_win_sysinternals_pssuspend_execution.kql) | medium | privilege-escalation, discovery, persistence, T1543.003 | DeviceProcessEvents |
| [Sysinternals PsSuspend Suspicious Execution](rules/windows/process_creation/proc_creation_win_sysinternals_pssuspend_susp_execution.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential File Overwrite Via Sysinternals SDelete](rules/windows/process_creation/proc_creation_win_sysinternals_sdelete.kql) | high | impact, T1485 | DeviceProcessEvents |
| [Potential Privilege Escalation To LOCAL SYSTEM](rules/windows/process_creation/proc_creation_win_sysinternals_susp_psexec_paexec_flags.kql) | high | resource-development, T1587.001 | DeviceProcessEvents |
| [Sysmon Configuration Update](rules/windows/process_creation/proc_creation_win_sysinternals_sysmon_config_update.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [Uninstall Sysinternals Sysmon](rules/windows/process_creation/proc_creation_win_sysinternals_sysmon_uninstall.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential Binary Impersonating Sysinternals Tools](rules/windows/process_creation/proc_creation_win_sysinternals_tools_masquerading.kql) | medium | execution, stealth, T1218, T1202, T1036.005 | DeviceProcessEvents |
| [Sysprep on AppData Folder](rules/windows/process_creation/proc_creation_win_sysprep_appdata.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Potential Signing Bypass Via Windows Developer Features](rules/windows/process_creation/proc_creation_win_systemsettingsadminflows_turn_on_dev_features.kql) | high | stealth | DeviceProcessEvents |
| [Suspicious Recursive Takeown](rules/windows/process_creation/proc_creation_win_takeown_recursive_own.kql) | medium | defense-impairment, T1222.001 | DeviceProcessEvents |
| [Tap Installer Execution](rules/windows/process_creation/proc_creation_win_tapinstall_execution.kql) | medium | exfiltration, T1048 | DeviceProcessEvents |
| [Taskkill Symantec Endpoint Protection](rules/windows/process_creation/proc_creation_win_taskkill_sep.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Loaded Module Enumeration Via Tasklist.EXE](rules/windows/process_creation/proc_creation_win_tasklist_module_enumeration.kql) | medium | T1003, credential-access | DeviceProcessEvents |
| [Taskmgr as LOCAL_SYSTEM](rules/windows/process_creation/proc_creation_win_taskmgr_localsystem.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Potentially Suspicious Command Targeting Teams Sensitive Files](rules/windows/process_creation/proc_creation_win_teams_suspicious_command_line_cred_access.kql) | medium | credential-access, T1528 | DeviceProcessEvents |
| [New Virtual Smart Card Created Via TpmVscMgr.EXE](rules/windows/process_creation/proc_creation_win_tpmvscmgr_add_virtual_smartcard.kql) | medium | execution | DeviceProcessEvents |
| [Suspicious TSCON Start as SYSTEM](rules/windows/process_creation/proc_creation_win_tscon_localsystem.kql) | high | command-and-control, T1219.002 | DeviceProcessEvents |
| [Suspicious RDP Redirect Using TSCON](rules/windows/process_creation/proc_creation_win_tscon_rdp_redirect.kql) | high | lateral-movement, T1563.002, T1021.001 | DeviceProcessEvents |
| [Potential RDP Session Hijacking Activity](rules/windows/process_creation/proc_creation_win_tscon_rdp_session_hijacking.kql) | medium | execution | DeviceProcessEvents |
| [UAC Bypass Using ChangePK and SLUI](rules/windows/process_creation/proc_creation_win_uac_bypass_changepk_slui.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using Disk Cleanup](rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Bypass UAC via CMSTP](rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp.kql) | high | privilege-escalation, stealth, T1548.002, T1218.003 | DeviceProcessEvents |
| [CMSTP UAC Bypass via COM Object Access](rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp_com_object_access.kql) | high | execution, privilege-escalation, stealth, T1548.002, T1218.003, G0069 | DeviceProcessEvents |
| [UAC Bypass Tools Using ComputerDefaults](rules/windows/process_creation/proc_creation_win_uac_bypass_computerdefaults.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using Consent and Comctl32 - Process](rules/windows/process_creation/proc_creation_win_uac_bypass_consent_comctl32.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using DismHost](rules/windows/process_creation/proc_creation_win_uac_bypass_dismhost.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using Event Viewer RecentViews](rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr_recentviews.kql) | high | privilege-escalation, stealth | DeviceProcessEvents |
| [Bypass UAC via Fodhelper.exe](rules/windows/process_creation/proc_creation_win_uac_bypass_fodhelper.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass via Windows Firewall Snap-In Hijack](rules/windows/process_creation/proc_creation_win_uac_bypass_hijacking_firwall_snap_in.kql) | medium | privilege-escalation, T1548 | DeviceProcessEvents |
| [UAC Bypass via ICMLuaUtil](rules/windows/process_creation/proc_creation_win_uac_bypass_icmluautil.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using IDiagnostic Profile](rules/windows/process_creation/proc_creation_win_uac_bypass_idiagnostic_profile.kql) | high | execution, privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using IEInstal - Process](rules/windows/process_creation/proc_creation_win_uac_bypass_ieinstal.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using MSConfig Token Modification - Process](rules/windows/process_creation/proc_creation_win_uac_bypass_msconfig_gui.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using NTFS Reparse Point - Process](rules/windows/process_creation/proc_creation_win_uac_bypass_ntfs_reparse_point.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using PkgMgr and DISM](rules/windows/process_creation/proc_creation_win_uac_bypass_pkgmgr_dism.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Potential UAC Bypass Via Sdclt.EXE](rules/windows/process_creation/proc_creation_win_uac_bypass_sdclt.kql) | medium | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [TrustedPath UAC Bypass Pattern](rules/windows/process_creation/proc_creation_win_uac_bypass_trustedpath.kql) | critical | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Abusing Winsat Path Parsing - Process](rules/windows/process_creation/proc_creation_win_uac_bypass_winsat.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass Using Windows Media Player - Process](rules/windows/process_creation/proc_creation_win_uac_bypass_wmp.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Bypass UAC via WSReset.exe](rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [UAC Bypass WSReset](rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset_integrity_level.kql) | high | privilege-escalation, T1548.002 | DeviceProcessEvents |
| [Use of UltraVNC Remote Access Software](rules/windows/process_creation/proc_creation_win_ultravnc.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Suspicious UltraVNC Execution](rules/windows/process_creation/proc_creation_win_ultravnc_susp_execution.kql) | high | lateral-movement, G0047, T1021.005 | DeviceProcessEvents |
| [Uninstall Crowdstrike Falcon Sensor](rules/windows/process_creation/proc_creation_win_uninstall_crowdstrike_falcon.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Uncommon Userinit Child Process](rules/windows/process_creation/proc_creation_win_userinit_uncommon_child_processes.kql) | high | privilege-escalation, T1037.001, persistence | DeviceProcessEvents |
| [Windows Credential Manager Access via VaultCmd](rules/windows/process_creation/proc_creation_win_vaultcmd_list_creds.kql) | medium | credential-access, T1555.004 | DeviceProcessEvents |
| [Verclsid.exe Runs COM Object](rules/windows/process_creation/proc_creation_win_verclsid_runs_com.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious VBoxDrvInst.exe Parameters](rules/windows/process_creation/proc_creation_win_virtualbox_vboxdrvinst_execution.kql) | medium | persistence, defense-impairment, T1112 | DeviceProcessEvents |
| [Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script](rules/windows/process_creation/proc_creation_win_vmware_toolbox_cmd_persistence.kql) | medium | execution, persistence, T1059 | DeviceProcessEvents |
| [Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script](rules/windows/process_creation/proc_creation_win_vmware_toolbox_cmd_persistence_susp.kql) | high | execution, persistence, T1059 | DeviceProcessEvents |
| [VMToolsd Suspicious Child Process](rules/windows/process_creation/proc_creation_win_vmware_vmtoolsd_susp_child_process.kql) | high | execution, persistence, T1059 | DeviceProcessEvents |
| [Potentially Suspicious Child Process Of VsCode](rules/windows/process_creation/proc_creation_win_vscode_child_processes_anomalies.kql) | medium | execution, stealth, T1218, T1202 | DeviceProcessEvents |
| [Visual Studio Code Tunnel Execution](rules/windows/process_creation/proc_creation_win_vscode_tunnel_execution.kql) | medium | command-and-control, T1071.001, T1219 | DeviceProcessEvents |
| [Visual Studio Code Tunnel Shell Execution](rules/windows/process_creation/proc_creation_win_vscode_tunnel_remote_shell_.kql) | medium | command-and-control, T1071.001 | DeviceProcessEvents |
| [Renamed Visual Studio Code Tunnel Execution](rules/windows/process_creation/proc_creation_win_vscode_tunnel_renamed_execution.kql) | high | command-and-control, T1071.001, T1219 | DeviceProcessEvents |
| [Visual Studio Code Tunnel Service Installation](rules/windows/process_creation/proc_creation_win_vscode_tunnel_service_install.kql) | medium | command-and-control, T1071.001 | DeviceProcessEvents |
| [Potential Binary Proxy Execution Via VSDiagnostics.EXE](rules/windows/process_creation/proc_creation_win_vsdiagnostics_execution_proxy.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Suspicious Vsls-Agent Command With AgentExtensionPath Load](rules/windows/process_creation/proc_creation_win_vslsagent_agentextensionpath_load.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Use of W32tm as Timer](rules/windows/process_creation/proc_creation_win_w32tm.kql) | high | discovery, T1124 | DeviceProcessEvents |
| [Wab Execution From Non Default Location](rules/windows/process_creation/proc_creation_win_wab_execution_from_non_default_location.kql) | high | execution, stealth | DeviceProcessEvents |
| [Wab/Wabmig Unusual Parent Or Child Processes](rules/windows/process_creation/proc_creation_win_wab_unusual_parents.kql) | high | execution, stealth | DeviceProcessEvents |
| [All Backups Deleted Via Wbadmin.EXE](rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.kql) | high | impact, T1490 | DeviceProcessEvents |
| [Windows Backup Deleted Via Wbadmin.EXE](rules/windows/process_creation/proc_creation_win_wbadmin_delete_backups.kql) | medium | impact, T1490 | DeviceProcessEvents |
| [Sensitive File Dump Via Wbadmin.EXE](rules/windows/process_creation/proc_creation_win_wbadmin_dump_sensitive_files.kql) | high | credential-access, T1003.003 | DeviceProcessEvents |
| [File Recovery From Backup Via Wbadmin.EXE](rules/windows/process_creation/proc_creation_win_wbadmin_restore_file.kql) | medium | impact, T1490 | DeviceProcessEvents |
| [Sensitive File Recovery From Backup Via Wbadmin.EXE](rules/windows/process_creation/proc_creation_win_wbadmin_restore_sensitive_files.kql) | high | credential-access, T1003.003 | DeviceProcessEvents |
| [Potentially Suspicious WebDAV LNK Execution](rules/windows/process_creation/proc_creation_win_webdav_lnk_execution.kql) | medium | execution, T1059.001, T1204 | DeviceProcessEvents |
| [Chopper Webshell Process Pattern](rules/windows/process_creation/proc_creation_win_webshell_chopper.kql) | high | persistence, discovery, T1505.003, T1018, T1033, T1087 | DeviceProcessEvents |
| [Webshell Hacking Activity Patterns](rules/windows/process_creation/proc_creation_win_webshell_hacking.kql) | high | persistence, discovery, T1505.003, T1018, T1033, T1087 | DeviceProcessEvents |
| [Webshell Detection With Command Line Keywords](rules/windows/process_creation/proc_creation_win_webshell_recon_commands_and_processes.kql) | high | persistence, discovery, T1505.003, T1018, T1033, T1087 | DeviceProcessEvents |
| [Suspicious Process By Web Server Process](rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.kql) | high | persistence, initial-access, T1505.003, T1190 | DeviceProcessEvents |
| [Webshell Tool Reconnaissance Activity](rules/windows/process_creation/proc_creation_win_webshell_tool_recon.kql) | high | persistence, T1505.003 | DeviceProcessEvents |
| [Potential Credential Dumping Via WER](rules/windows/process_creation/proc_creation_win_werfault_lsass_shtinkering.kql) | high | credential-access, T1003.001 | DeviceProcessEvents |
| [Potential ReflectDebugger Content Execution Via WerFault.EXE](rules/windows/process_creation/proc_creation_win_werfault_reflect_debugger_exec.kql) | medium | execution, stealth, T1036 | DeviceProcessEvents |
| [Suspicious Child Process Of Wermgr.EXE](rules/windows/process_creation/proc_creation_win_wermgr_susp_child_process.kql) | high | privilege-escalation, stealth, T1055, T1036 | DeviceProcessEvents |
| [Suspicious Execution Location Of Wermgr.EXE](rules/windows/process_creation/proc_creation_win_wermgr_susp_exec_location.kql) | high | execution | DeviceProcessEvents |
| [Suspicious File Download From IP Via Wget.EXE](rules/windows/process_creation/proc_creation_win_wget_download_direct_ip.kql) | high | execution | DeviceProcessEvents |
| [Suspicious File Download From File Sharing Domain Via Wget.EXE](rules/windows/process_creation/proc_creation_win_wget_download_susp_file_sharing_domains.kql) | high | execution | DeviceProcessEvents |
| [Suspicious File Download From IP Via Wget.EXE - Paths](rules/windows/process_creation/proc_creation_win_wget_download_susp_locations.kql) | high | execution | DeviceProcessEvents |
| [Enumerate All Information With Whoami.EXE](rules/windows/process_creation/proc_creation_win_whoami_all_execution.kql) | medium | discovery, T1033 | DeviceProcessEvents |
| [Whoami.EXE Execution From Privileged Process](rules/windows/process_creation/proc_creation_win_whoami_execution_from_high_priv_process.kql) | high | privilege-escalation, discovery, T1033 | DeviceProcessEvents |
| [Group Membership Reconnaissance Via Whoami.EXE](rules/windows/process_creation/proc_creation_win_whoami_groups_discovery.kql) | medium | discovery, T1033 | DeviceProcessEvents |
| [Whoami.EXE Execution With Output Option](rules/windows/process_creation/proc_creation_win_whoami_output.kql) | medium | discovery, T1033 | DeviceProcessEvents |
| [Whoami.EXE Execution Anomaly](rules/windows/process_creation/proc_creation_win_whoami_parent_anomaly.kql) | medium | discovery, T1033 | DeviceProcessEvents |
| [Security Privileges Enumeration Via Whoami.EXE](rules/windows/process_creation/proc_creation_win_whoami_priv_discovery.kql) | high | privilege-escalation, discovery, T1033 | DeviceProcessEvents |
| [Suspicious WindowsTerminal Child Processes](rules/windows/process_creation/proc_creation_win_windows_terminal_susp_children.kql) | medium | execution, persistence | DeviceProcessEvents |
| [Add New Download Source To Winget](rules/windows/process_creation/proc_creation_win_winget_add_custom_source.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Add Insecure Download Source To Winget](rules/windows/process_creation/proc_creation_win_winget_add_insecure_custom_source.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Add Potential Suspicious New Download Source To Winget](rules/windows/process_creation/proc_creation_win_winget_add_susp_custom_source.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Install New Package Via Winget Local Manifest](rules/windows/process_creation/proc_creation_win_winget_local_install_via_manifest.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Winrar Compressing Dump Files](rules/windows/process_creation/proc_creation_win_winrar_exfil_dmp_files.kql) | medium | collection, T1560.001 | DeviceProcessEvents |
| [Potentially Suspicious Child Process Of WinRAR.EXE](rules/windows/process_creation/proc_creation_win_winrar_susp_child_process.kql) | medium | execution, T1203 | DeviceProcessEvents |
| [WinRAR Execution in Non-Standard Folder](rules/windows/process_creation/proc_creation_win_winrar_uncommon_folder_execution.kql) | medium | collection, T1560.001 | DeviceProcessEvents |
| [AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl](rules/windows/process_creation/proc_creation_win_winrm_awl_bypass.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [Remote Code Execute via Winrm.vbs](rules/windows/process_creation/proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs.kql) | medium | stealth, T1216 | DeviceProcessEvents |
| [Remote PowerShell Session Host Process (WinRM)](rules/windows/process_creation/proc_creation_win_winrm_remote_powershell_session_process.kql) | medium | execution, lateral-movement, T1059.001, T1021.006 | DeviceProcessEvents |
| [Suspicious Processes Spawned by WinRM](rules/windows/process_creation/proc_creation_win_winrm_susp_child_process.kql) | high | T1190, initial-access, persistence, privilege-escalation | DeviceProcessEvents |
| [Compress Data and Lock With Password for Exfiltration With WINZIP](rules/windows/process_creation/proc_creation_win_winzip_password_compression.kql) | medium | collection, T1560.001 | DeviceProcessEvents |
| [WMI Backdoor Exchange Transport Agent](rules/windows/process_creation/proc_creation_win_wmi_backdoor_exchange_transport_agent.kql) | critical | privilege-escalation, persistence, T1546.003 | DeviceProcessEvents |
| [WMI Persistence - Script Event Consumer](rules/windows/process_creation/proc_creation_win_wmi_persistence_script_event_consumer.kql) | medium | persistence, privilege-escalation, T1546.003 | DeviceProcessEvents |
| [NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.kql) | high | privilege-escalation, persistence, T1546.003 | DeviceProcessEvents |
| [Potential Windows Defender Tampering Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_namespace_defender.kql) | high | execution, defense-impairment, T1047, T1685 | DeviceProcessEvents |
| [Process Creation Attempt via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_process_creation.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Computer System Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_computersystem.kql) | medium | discovery, execution, T1047 | DeviceProcessEvents |
| [Hardware Model Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_csproduct.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Windows Hotfix Updates Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_hotfix.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Potential Process Reconnaissance via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_process.kql) | medium | execution, T1047, discovery, T1057 | DeviceProcessEvents |
| [Potential Product Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_product.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Potential Product Class Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_product_class.kql) | medium | execution, T1047, discovery, T1082 | DeviceProcessEvents |
| [Service Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_service.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Uncommon System Information Discovery Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_system_info_uncommon.kql) | medium | discovery, T1082 | DeviceProcessEvents |
| [Potential Unquoted Service Path Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_unquoted_service_search.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [System Disk And Volume Reconnaissance Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_recon_volume.kql) | medium | execution, discovery, T1047, T1082 | DeviceProcessEvents |
| [WMIC Remote Command Execution](rules/windows/process_creation/proc_creation_win_wmic_remote_execution.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Service Started/Stopped Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_service_manipulation.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Suspicious WMIC Execution Via Office Process](rules/windows/process_creation/proc_creation_win_wmic_susp_execution_via_office_process.kql) | high | stealth, T1204.002, T1047, T1218.010, execution | DeviceProcessEvents |
| [Suspicious Process Created Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.kql) | high | execution, T1047 | DeviceProcessEvents |
| [Application Termination Attempt via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_terminate_application.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Application Removed Via Wmic.EXE](rules/windows/process_creation/proc_creation_win_wmic_uninstall_application.kql) | medium | execution, T1047 | DeviceProcessEvents |
| [Potential Tampering With Security Products Via WMIC](rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.kql) | high | defense-impairment, T1685 | DeviceProcessEvents |
| [Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell](rules/windows/process_creation/proc_creation_win_wmiprvse_spawns_powershell.kql) | medium | execution, T1047, T1059.001 | DeviceProcessEvents |
| [Suspicious WmiPrvSE Child Process](rules/windows/process_creation/proc_creation_win_wmiprvse_susp_child_processes.kql) | high | execution, stealth, T1047, T1204.002, T1218.010 | DeviceProcessEvents |
| [UEFI Persistence Via Wpbbin - ProcessCreation](rules/windows/process_creation/proc_creation_win_wpbbin_potential_persistence.kql) | high | persistence, stealth, T1542.001 | DeviceProcessEvents |
| [Potential Dropper Script Execution Via WScript/CScript/MSHTA](rules/windows/process_creation/proc_creation_win_wscript_cscript_mshta_dropper.kql) | medium | execution, T1059.005, T1059.007 | DeviceProcessEvents |
| [Cscript/Wscript Potentially Suspicious Child Process](rules/windows/process_creation/proc_creation_win_wscript_cscript_susp_child_processes.kql) | medium | execution | DeviceProcessEvents |
| [Cscript/Wscript Uncommon Script Extension Execution](rules/windows/process_creation/proc_creation_win_wscript_cscript_uncommon_extension_exec.kql) | high | execution, T1059.005, T1059.007 | DeviceProcessEvents |
| [WSL Child Process Anomaly](rules/windows/process_creation/proc_creation_win_wsl_child_processes_anomalies.kql) | medium | execution, stealth, T1218, T1202 | DeviceProcessEvents |
| [Proxy Execution Via Wuauclt.EXE](rules/windows/process_creation/proc_creation_win_wuauclt_dll_loading.kql) | high | stealth, T1218, execution | DeviceProcessEvents |
| [Suspicious Windows Update Agent Empty Cmdline](rules/windows/process_creation/proc_creation_win_wuauclt_no_cli_flags_execution.kql) | high | stealth, T1036 | DeviceProcessEvents |
| [Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths](rules/windows/process_creation/proc_creation_win_wusa_cab_files_extraction_from_susp_paths.kql) | high | execution | DeviceProcessEvents |
| [Wusa.EXE Executed By Parent Process Located In Suspicious Location](rules/windows/process_creation/proc_creation_win_wusa_susp_parent_execution.kql) | high | execution | DeviceProcessEvents |
| [Xwizard.EXE Execution From Non-Default Location](rules/windows/process_creation/proc_creation_win_xwizard_execution_non_default_location.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [COM Object Execution via Xwizard.EXE](rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential Persistence Via Disk Cleanup Handler - Registry](rules/windows/registry/registry_add/registry_add_persistence_disk_cleanup_handler_entry.kql) | medium | persistence | DeviceRegistryEvents |
| [Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted](rules/windows/registry/registry_delete/registry_delete_enable_windows_recall.kql) | medium | collection, T1113 | DeviceRegistryEvents |
| [Folder Removed From Exploit Guard ProtectedFolders List - Registry](rules/windows/registry/registry_delete/registry_delete_exploit_guard_protected_folders.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Terminal Server Client Connection History Cleared - Registry](rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.kql) | high | persistence, stealth, defense-impairment, T1070, T1112 | DeviceRegistryEvents |
| [Removal Of AMSI Provider Registry Keys](rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Removal of Potential COM Hijacking Registry Keys](rules/windows/registry/registry_delete/registry_delete_removal_com_hijacking_registry_key.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Removal Of Index Value to Hide Schedule Task - Registry](rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_index_value_removal.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Removal Of SD Value to Hide Schedule Task - Registry](rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Creation of a Local Hidden User Account by Registry](rules/windows/registry/registry_event/registry_event_add_local_hidden_user.kql) | high | persistence, T1136.001 | DeviceRegistryEvents |
| [UAC Bypass Via Wsreset](rules/windows/registry/registry_event/registry_event_bypass_via_wsreset.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [CMSTP App Paths Registry Key Modification](rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.kql) | high | execution, stealth, T1218.003, G0069 | DeviceRegistryEvents |
| [Wdigest CredGuard Registry Modification](rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Esentutl Volume Shadow Copy Service Keys](rules/windows/registry/registry_event/registry_event_esentutl_volume_shadow_copy_service_keys.kql) | high | credential-access, T1003.002 | DeviceRegistryEvents |
| [Windows Credential Editor Registry](rules/windows/registry/registry_event/registry_event_hack_wce_reg.kql) | critical | credential-access, T1003.001, S0005 | DeviceRegistryEvents |
| [HybridConnectionManager Service Installation - Registry](rules/windows/registry/registry_event/registry_event_hybridconnectionmgr_svc_installation.kql) | high | resource-development, T1608 | DeviceRegistryEvents |
| [Registry Entries For Azorult Malware](rules/windows/registry/registry_event/registry_event_mal_azorult.kql) | critical | persistence, execution, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential Qakbot Registry Activity](rules/windows/registry/registry_event/registry_event_malware_qakbot_registry.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Path To Screensaver Binary Modified](rules/windows/registry/registry_event/registry_event_modify_screensaver_binary_path.kql) | medium | persistence, privilege-escalation, T1546.002 | DeviceRegistryEvents |
| [Narrator's Feedback-Hub Persistence](rules/windows/registry/registry_event/registry_event_narrator_feedback_persistance.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [NetNTLM Downgrade Attack - Registry](rules/windows/registry/registry_event/registry_event_net_ntlm_downgrade.kql) | high | persistence, defense-impairment, T1685, T1112 | DeviceRegistryEvents |
| [Office Application Startup - Office Test](rules/windows/registry/registry_event/registry_event_office_test_regadd.kql) | medium | persistence, T1137.002 | DeviceRegistryEvents |
| [Windows Registry Trust Record Modification](rules/windows/registry/registry_event/registry_event_office_trust_record_modification.kql) | medium | initial-access, T1566.001 | DeviceRegistryEvents |
| [New PortProxy Registry Entry Added](rules/windows/registry/registry_event/registry_event_portproxy_registry_key.kql) | medium | lateral-movement, command-and-control, T1090 | DeviceRegistryEvents |
| [RedMimicry Winnti Playbook Registry Manipulation](rules/windows/registry/registry_event/registry_event_redmimicry_winnti_reg.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [WINEKEY Registry Modification](rules/windows/registry/registry_event/registry_event_runkey_winekey.kql) | high | privilege-escalation, persistence, T1547 | DeviceRegistryEvents |
| [Run Once Task Configuration in Registry](rules/windows/registry/registry_event/registry_event_runonce_persistence.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Shell Open Registry Keys Manipulation](rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.kql) | high | persistence, privilege-escalation, T1548.002, T1546.001 | DeviceRegistryEvents |
| [Potential Credential Dumping Via LSASS SilentProcessExit Technique](rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.kql) | critical | credential-access, T1003.001 | DeviceRegistryEvents |
| [Security Support Provider (SSP) Added to LSA Configuration](rules/windows/registry/registry_event/registry_event_ssp_added_lsa_config.kql) | high | privilege-escalation, persistence, T1547.005 | DeviceRegistryEvents |
| [Sticky Key Like Backdoor Usage - Registry](rules/windows/registry/registry_event/registry_event_stickykey_like_backdoor.kql) | critical | privilege-escalation, persistence, T1546.008 | DeviceRegistryEvents |
| [Atbroker Registry Change](rules/windows/registry/registry_event/registry_event_susp_atbroker_change.kql) | medium | privilege-escalation, stealth, T1218, persistence, T1547 | DeviceRegistryEvents |
| [Suspicious Run Key from Download](rules/windows/registry/registry_event/registry_event_susp_download_run_key.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [DLL Load via LSASS](rules/windows/registry/registry_event/registry_event_susp_lsass_dll_load.kql) | high | privilege-escalation, execution, persistence, T1547.008 | DeviceRegistryEvents |
| [Suspicious Camera and Microphone Access](rules/windows/registry/registry_event/registry_event_susp_mic_cam_access.kql) | high | collection, T1125, T1123 | DeviceRegistryEvents |
| [Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback](rules/windows/registry/registry_event/registry_set_enable_anonymous_connection.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Registry Persistence via Service in Safe Mode](rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.kql) | high | stealth, T1564.001 | DeviceRegistryEvents |
| [Add Port Monitor Persistence in Registry](rules/windows/registry/registry_set/registry_set_add_port_monitor.kql) | medium | privilege-escalation, persistence, T1547.010 | DeviceRegistryEvents |
| [Add Debugger Entry To AeDebug For Persistence](rules/windows/registry/registry_set/registry_set_aedebug_persistence.kql) | medium | persistence | DeviceRegistryEvents |
| [Allow RDP Remote Assistance Feature](rules/windows/registry/registry_set/registry_set_allow_rdp_remote_assistance_feature.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential AMSI COM Server Hijacking](rules/windows/registry/registry_set/registry_set_amsi_com_hijack.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Classes Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_classes.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Common Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_common.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [CurrentControlSet Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentcontrolset.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [CurrentVersion Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [CurrentVersion NT Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Internet Explorer Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_internet_explorer.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Office Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_office.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Session Manager Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_session_manager.kql) | medium | privilege-escalation, persistence, T1547.001, T1546.009 | DeviceRegistryEvents |
| [System Scripts Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_system_scripts.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [WinSock2 Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_winsock2.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Wow6432Node CurrentVersion Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Wow6432Node Classes Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node_classes.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Wow6432Node Windows NT CurrentVersion Autorun Keys Modification](rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node_currentversion.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [New BgInfo.EXE Custom DB Path Registry Configuration](rules/windows/registry/registry_set/registry_set_bginfo_custom_db.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [New BgInfo.EXE Custom VBScript Registry Configuration](rules/windows/registry/registry_set/registry_set_bginfo_custom_vbscript.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [New BgInfo.EXE Custom WMI Query Registry Configuration](rules/windows/registry/registry_set/registry_set_bginfo_custom_wmi_query.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Bypass UAC Using DelegateExecute](rules/windows/registry/registry_set/registry_set_bypass_uac_using_delegateexecute.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [Bypass UAC Using Event Viewer](rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.kql) | high | privilege-escalation, persistence, T1547.010 | DeviceRegistryEvents |
| [Bypass UAC Using SilentCleanup Task](rules/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [Default RDP Port Changed to Non Standard Port](rules/windows/registry/registry_set/registry_set_change_rdp_port.kql) | high | privilege-escalation, persistence, T1547.010 | DeviceRegistryEvents |
| [IE Change Domain Zone](rules/windows/registry/registry_set/registry_set_change_security_zones.kql) | medium | persistence, T1137 | DeviceRegistryEvents |
| [Sysmon Driver Altitude Change](rules/windows/registry/registry_set/registry_set_change_sysmon_driver_altitude.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Change Winevt Channel Access Permission Via Registry](rules/windows/registry/registry_set/registry_set_change_winevt_channelaccess.kql) | high | defense-impairment, T1685.001 | DeviceRegistryEvents |
| [Running Chrome VPN Extensions via the Registry 2 VPN Extension](rules/windows/registry/registry_set/registry_set_chrome_extension.kql) | high | initial-access, persistence, T1133 | DeviceRegistryEvents |
| [ClickOnce Trust Prompt Tampering](rules/windows/registry/registry_set/registry_set_clickonce_trust_prompt.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential CobaltStrike Service Installations - Registry](rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.kql) | high | persistence, execution, privilege-escalation, lateral-movement, T1021.002, T1543.003, T1569.002 | DeviceRegistryEvents |
| [COM Hijack via Sdclt](rules/windows/registry/registry_set/registry_set_comhijack_sdclt.kql) | high | persistence, privilege-escalation, T1546, T1548 | DeviceRegistryEvents |
| [CrashControl CrashDump Disabled](rules/windows/registry/registry_set/registry_set_crashdump_disabled.kql) | medium | persistence, stealth, defense-impairment, T1564, T1112 | DeviceRegistryEvents |
| [Service Binary in Suspicious Folder](rules/windows/registry/registry_set/registry_set_creation_service_susp_folder.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Custom File Open Handler Executes PowerShell](rules/windows/registry/registry_set/registry_set_custom_file_open_handler_powershell_execution.kql) | high | stealth, T1202 | DeviceRegistryEvents |
| [Potential Registry Persistence Attempt Via DbgManagedDebugger](rules/windows/registry/registry_set/registry_set_dbgmanageddebugger_persistence.kql) | medium | privilege-escalation, persistence, execution, stealth, T1574 | DeviceRegistryEvents |
| [Windows Defender Exclusions Added - Registry](rules/windows/registry/registry_set/registry_set_defender_exclusions.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Potentially Suspicious Desktop Background Change Via Registry](rules/windows/registry/registry_set/registry_set_desktop_background_change.kql) | medium | persistence, impact, defense-impairment, T1112, T1491.001 | DeviceRegistryEvents |
| [Antivirus Filter Driver Disallowed On Dev Drive - Registry](rules/windows/registry/registry_set/registry_set_devdrv_disallow_antivirus_filter.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Windows Hypervisor Enforced Code Integrity Disabled](rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedcodeintegrity_disabled.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Hypervisor Enforced Paging Translation Disabled](rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedpagingtranslation_disabled.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [DHCP Callout DLL Installation](rules/windows/registry/registry_set/registry_set_dhcp_calloutdll.kql) | high | privilege-escalation, persistence, execution, stealth, defense-impairment, T1574.001, T1112 | DeviceRegistryEvents |
| [Disable Administrative Share Creation at Startup](rules/windows/registry/registry_set/registry_set_disable_administrative_share.kql) | medium | stealth, T1070.005 | DeviceRegistryEvents |
| [Potential AutoLogger Sessions Tampering](rules/windows/registry/registry_set/registry_set_disable_autologger_sessions.kql) | high | defense-impairment, T1685.001 | DeviceRegistryEvents |
| [Disable Microsoft Defender Firewall via Registry](rules/windows/registry/registry_set/registry_set_disable_defender_firewall.kql) | medium | defense-impairment, T1686.003 | DeviceRegistryEvents |
| [Disable Internal Tools or Feature in Registry](rules/windows/registry/registry_set/registry_set_disable_function_user.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Disable Macro Runtime Scan Scope](rules/windows/registry/registry_set/registry_set_disable_macroruntimescanscope.kql) | high | defense-impairment | DeviceRegistryEvents |
| [Disable Privacy Settings Experience in Registry](rules/windows/registry/registry_set/registry_set_disable_privacy_settings_experience.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Disable Windows Security Center Notifications](rules/windows/registry/registry_set/registry_set_disable_security_center_notifications.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Registry Disable System Restore](rules/windows/registry/registry_set/registry_set_disable_system_restore.kql) | high | impact, T1490 | DeviceRegistryEvents |
| [Windows Defender Service Disabled - Registry](rules/windows/registry/registry_set/registry_set_disable_windows_defender_service.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Disable Windows Firewall by Registry](rules/windows/registry/registry_set/registry_set_disable_windows_firewall.kql) | medium | defense-impairment, T1686.003 | DeviceRegistryEvents |
| [Disable Windows Event Logging Via Registry](rules/windows/registry/registry_set/registry_set_disable_winevt_logging.kql) | high | defense-impairment, T1685.001 | DeviceRegistryEvents |
| [Disable Exploit Guard Network Protection on Windows Defender](rules/windows/registry/registry_set/registry_set_disabled_exploit_guard_net_protection_on_ms_defender.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Disabled Windows Defender Eventlog](rules/windows/registry/registry_set/registry_set_disabled_microsoft_defender_eventlog.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Disable PUA Protection on Windows Defender](rules/windows/registry/registry_set/registry_set_disabled_pua_protection_on_microsoft_defender.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Disable Tamper Protection on Windows Defender](rules/windows/registry/registry_set/registry_set_disabled_tamper_protection_on_microsoft_defender.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Add DisallowRun Execution to Registry](rules/windows/registry/registry_set/registry_set_disallowrun_execution.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Persistence Via Disk Cleanup Handler - Autorun](rules/windows/registry/registry_set/registry_set_disk_cleanup_handler_autorun_persistence.kql) | medium | persistence | DeviceRegistryEvents |
| [DNS-over-HTTPS Enabled by Registry](rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.kql) | medium | persistence, stealth, defense-impairment, T1140, T1112 | DeviceRegistryEvents |
| [New DNS ServerLevelPluginDll Installed](rules/windows/registry/registry_set/registry_set_dns_server_level_plugin_dll.kql) | high | privilege-escalation, persistence, execution, stealth, defense-impairment, T1574.001, T1112 | DeviceRegistryEvents |
| [ETW Logging Disabled In .NET Processes - Sysmon Registry](rules/windows/registry/registry_set/registry_set_dot_net_etw_tamper.kql) | high | persistence, defense-impairment, T1112, T1685 | DeviceRegistryEvents |
| [Directory Service Restore Mode(DSRM) Registry Value Tampering](rules/windows/registry/registry_set/registry_set_dsrm_tampering.kql) | high | credential-access, persistence, defense-impairment, T1556 | DeviceRegistryEvents |
| [Periodic Backup For System Registry Hives Enabled](rules/windows/registry/registry_set/registry_set_enable_periodic_backup.kql) | medium | collection, T1113 | DeviceRegistryEvents |
| [Windows Recall Feature Enabled - Registry](rules/windows/registry/registry_set/registry_set_enable_windows_recall.kql) | medium | collection, T1113 | DeviceRegistryEvents |
| [Enabling COR Profiler Environment Variables](rules/windows/registry/registry_set/registry_set_enabling_cor_profiler_env_variables.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.012 | DeviceRegistryEvents |
| [Scripted Diagnostics Turn Off Check Enabled - Registry](rules/windows/registry/registry_set/registry_set_enabling_turnoffcheck.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Potential EventLog File Location Tampering](rules/windows/registry/registry_set/registry_set_evtx_file_key_tamper.kql) | high | defense-impairment, T1685.001 | DeviceRegistryEvents |
| [Suspicious Application Allowed Through Exploit Guard](rules/windows/registry/registry_set/registry_set_exploit_guard_susp_allowed_apps.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Change User Account Associated with the FAX Service](rules/windows/registry/registry_set/registry_set_fax_change_service_user.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Change the Fax Dll](rules/windows/registry/registry_set/registry_set_fax_dll_persistance.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [New File Association Using Exefile](rules/windows/registry/registry_set/registry_set_file_association_exefile.kql) | high | stealth | DeviceRegistryEvents |
| [Add Debugger Entry To Hangs Key For Persistence](rules/windows/registry/registry_set/registry_set_hangs_debugger_persistence.kql) | high | persistence | DeviceRegistryEvents |
| [Persistence Via Hhctrl.ocx](rules/windows/registry/registry_set/registry_set_hhctrl_persistence.kql) | high | persistence | DeviceRegistryEvents |
| [Registry Modification to Hidden File Extension](rules/windows/registry/registry_set/registry_set_hidden_extention.kql) | medium | persistence, T1137 | DeviceRegistryEvents |
| [Displaying Hidden Files Feature Disabled](rules/windows/registry/registry_set/registry_set_hide_file.kql) | medium | stealth, T1564.001 | DeviceRegistryEvents |
| [Registry Hide Function from User](rules/windows/registry/registry_set/registry_set_hide_function_user.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Hide Schedule Task Via Index Value Tamper](rules/windows/registry/registry_set/registry_set_hide_scheduled_task_via_index_tamper.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Driver Added To Disallowed Images In HVCI - Registry](rules/windows/registry/registry_set/registry_set_hvci_disallowed_images.kql) | high | stealth | DeviceRegistryEvents |
| [IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols](rules/windows/registry/registry_set/registry_set_ie_security_zone_protocol_defaults_downgrade.kql) | high | stealth | DeviceRegistryEvents |
| [Uncommon Extension In Keyboard Layout IME File Registry Value](rules/windows/registry/registry_set/registry_set_ime_non_default_extension.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Suspicious Path In Keyboard Layout IME File Registry Value](rules/windows/registry/registry_set/registry_set_ime_suspicious_paths.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [New Root or CA or AuthRoot Certificate to Store](rules/windows/registry/registry_set/registry_set_install_root_or_ca_certificat.kql) | medium | impact, T1490 | DeviceRegistryEvents |
| [Internet Explorer DisableFirstRunCustomize Enabled](rules/windows/registry/registry_set/registry_set_internet_explorer_disable_first_run_customize.kql) | medium | defense-impairment | DeviceRegistryEvents |
| [Potential Ransomware Activity Using LegalNotice Message](rules/windows/registry/registry_set/registry_set_legalnotice_susp_message.kql) | high | impact, T1491.001 | DeviceRegistryEvents |
| [Lolbas OneDriveStandaloneUpdater.exe Proxy Download](rules/windows/registry/registry_set/registry_set_lolbin_onedrivestandaloneupdater.kql) | high | command-and-control, T1105 | DeviceRegistryEvents |
| [RestrictedAdminMode Registry Value Tampering](rules/windows/registry/registry_set/registry_set_lsa_disablerestrictedadmin.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Lsass Full Dump Request Via DumpType Registry Settings](rules/windows/registry/registry_set/registry_set_lsass_usermode_dumping.kql) | high | credential-access, T1003.001 | DeviceRegistryEvents |
| [NET NGenAssemblyUsageLog Registry Key Tamper](rules/windows/registry/registry_set/registry_set_net_cli_ngenassemblyusagelog.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [New Netsh Helper DLL Registered From A Suspicious Location](rules/windows/registry/registry_set/registry_set_netsh_help_dll_persistence_susp_location.kql) | high | privilege-escalation, persistence, T1546.007 | DeviceRegistryEvents |
| [Potential Persistence Via Netsh Helper DLL - Registry](rules/windows/registry/registry_set/registry_set_netsh_helper_dll_potential_persistence.kql) | medium | privilege-escalation, persistence, T1546.007 | DeviceRegistryEvents |
| [Potential Credential Dumping Attempt Using New NetworkProvider - REG](rules/windows/registry/registry_set/registry_set_new_network_provider.kql) | medium | credential-access, T1003 | DeviceRegistryEvents |
| [Potentially Suspicious ODBC Driver Registered](rules/windows/registry/registry_set/registry_set_odbc_driver_registered_susp.kql) | high | credential-access, persistence, T1003 | DeviceRegistryEvents |
| [Trust Access Disable For VBApplications](rules/windows/registry/registry_set/registry_set_office_access_vbom_tamper.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Microsoft Office Protected View Disabled](rules/windows/registry/registry_set/registry_set_office_disable_protected_view_features.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Python Function Execution Security Warning Disabled In Excel - Registry](rules/windows/registry/registry_set/registry_set_office_disable_python_security_warnings.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Enable Microsoft Dynamic Data Exchange](rules/windows/registry/registry_set/registry_set_office_enable_dde.kql) | medium | execution, T1559.002 | DeviceRegistryEvents |
| [Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting](rules/windows/registry/registry_set/registry_set_office_outlook_enable_load_macro_provider_on_boot.kql) | high | privilege-escalation, persistence, command-and-control, T1137, T1008, T1546 | DeviceRegistryEvents |
| [Outlook Macro Execution Without Warning Setting Enabled](rules/windows/registry/registry_set/registry_set_office_outlook_enable_macro_execution.kql) | high | privilege-escalation, persistence, command-and-control, T1137, T1008, T1546 | DeviceRegistryEvents |
| [Outlook EnableUnsafeClientMailRules Setting Enabled - Registry](rules/windows/registry/registry_set/registry_set_office_outlook_enable_unsafe_client_mail_rules.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Outlook Security Settings Updated - Registry](rules/windows/registry/registry_set/registry_set_office_outlook_security_settings.kql) | medium | persistence, T1137 | DeviceRegistryEvents |
| [Macro Enabled In A Potentially Suspicious Document](rules/windows/registry/registry_set/registry_set_office_trust_record_susp_location.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Uncommon Microsoft Office Trusted Location Added](rules/windows/registry/registry_set/registry_set_office_trusted_location_uncommon.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Office Macros Warning Disabled](rules/windows/registry/registry_set/registry_set_office_vba_warnings_tamper.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential Persistence Via New AMSI Providers - Registry](rules/windows/registry/registry_set/registry_set_persistence_amsi_providers.kql) | medium | persistence | DeviceRegistryEvents |
| [Potential Persistence Via AppCompat RegisterAppRestart Layer](rules/windows/registry/registry_set/registry_set_persistence_app_cpmpat_layer_registerapprestart.kql) | medium | privilege-escalation, persistence, T1546.011 | DeviceRegistryEvents |
| [Potential Persistence Via App Paths Default Property](rules/windows/registry/registry_set/registry_set_persistence_app_paths.kql) | high | privilege-escalation, persistence, T1546.012 | DeviceRegistryEvents |
| [Potential Persistence Using DebugPath](rules/windows/registry/registry_set/registry_set_persistence_appx_debugger.kql) | medium | privilege-escalation, persistence, T1546.015 | DeviceRegistryEvents |
| [Potential Persistence Via AutodialDLL](rules/windows/registry/registry_set/registry_set_persistence_autodial_dll.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Persistence Via CHM Helper DLL](rules/windows/registry/registry_set/registry_set_persistence_chm.kql) | high | persistence | DeviceRegistryEvents |
| [Potential COM Object Hijacking Via TreatAs Subkey - Registry](rules/windows/registry/registry_set/registry_set_persistence_com_key_linking.kql) | medium | privilege-escalation, persistence, T1546.015 | DeviceRegistryEvents |
| [Potential PSFactoryBuffer COM Hijacking](rules/windows/registry/registry_set/registry_set_persistence_comhijack_psfactorybuffer.kql) | high | privilege-escalation, persistence, T1546.015 | DeviceRegistryEvents |
| [Potential Persistence Via Custom Protocol Handler](rules/windows/registry/registry_set/registry_set_persistence_custom_protocol_handler.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential Persistence Via Event Viewer Events.asp](rules/windows/registry/registry_set/registry_set_persistence_event_viewer_events_asp.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential Persistence Via GlobalFlags](rules/windows/registry/registry_set/registry_set_persistence_globalflags.kql) | high | privilege-escalation, persistence, T1546.012 | DeviceRegistryEvents |
| [Register New IFiltre For Persistence](rules/windows/registry/registry_set/registry_set_persistence_ifilter.kql) | medium | persistence | DeviceRegistryEvents |
| [Potential Persistence Via Logon Scripts - Registry](rules/windows/registry/registry_set/registry_set_persistence_logon_scripts_userinitmprlogonscript.kql) | medium | privilege-escalation, T1037.001, persistence, lateral-movement | DeviceRegistryEvents |
| [Potential Persistence Via LSA Extensions](rules/windows/registry/registry_set/registry_set_persistence_lsa_extension.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Persistence Via Mpnotify](rules/windows/registry/registry_set/registry_set_persistence_mpnotify.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Persistence Via MyComputer Registry Keys](rules/windows/registry/registry_set/registry_set_persistence_mycomputer.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Persistence Via DLLPathOverride](rules/windows/registry/registry_set/registry_set_persistence_natural_language.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Persistence Via Visual Studio Tools for Office](rules/windows/registry/registry_set/registry_set_persistence_office_vsto.kql) | medium | T1137.006, persistence | DeviceRegistryEvents |
| [Potential Persistence Via Outlook Home Page](rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential Persistence Via Outlook Today Page](rules/windows/registry/registry_set/registry_set_persistence_outlook_todaypage.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential WerFault ReflectDebugger Registry Value Abuse](rules/windows/registry/registry_set/registry_set_persistence_reflectdebugger.kql) | high | stealth, T1036.003 | DeviceRegistryEvents |
| [Potential Persistence Via Scrobj.dll COM Hijacking](rules/windows/registry/registry_set/registry_set_persistence_scrobj_dll.kql) | medium | privilege-escalation, persistence, T1546.015 | DeviceRegistryEvents |
| [Potential Persistence Via Shim Database Modification](rules/windows/registry/registry_set/registry_set_persistence_shim_database.kql) | medium | privilege-escalation, persistence, T1546.011 | DeviceRegistryEvents |
| [Suspicious Shim Database Patching Activity](rules/windows/registry/registry_set/registry_set_persistence_shim_database_susp_application.kql) | high | privilege-escalation, persistence, T1546.011 | DeviceRegistryEvents |
| [Potential Persistence Via Shim Database In Uncommon Location](rules/windows/registry/registry_set/registry_set_persistence_shim_database_uncommon_location.kql) | high | privilege-escalation, persistence, T1546.011 | DeviceRegistryEvents |
| [Potential Persistence Via TypedPaths](rules/windows/registry/registry_set/registry_set_persistence_typed_paths.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Persistence Via Excel Add-in - Registry](rules/windows/registry/registry_set/registry_set_persistence_xll.kql) | high | persistence, T1137.006 | DeviceRegistryEvents |
| [Potential Attachment Manager Settings Associations Tamper](rules/windows/registry/registry_set/registry_set_policies_associations_tamper.kql) | high | defense-impairment | DeviceRegistryEvents |
| [Potential Attachment Manager Settings Attachments Tamper](rules/windows/registry/registry_set/registry_set_policies_attachments_tamper.kql) | high | defense-impairment | DeviceRegistryEvents |
| [PowerShell as a Service in Registry](rules/windows/registry/registry_set/registry_set_powershell_as_service.kql) | high | execution, T1569.002 | DeviceRegistryEvents |
| [Potential PowerShell Execution Policy Tampering](rules/windows/registry/registry_set/registry_set_powershell_execution_policy.kql) | medium | defense-impairment | DeviceRegistryEvents |
| [Suspicious PowerShell In Registry Run Keys](rules/windows/registry/registry_set/registry_set_powershell_in_run_keys.kql) | medium | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [PowerShell Logging Disabled Via Registry Key Tampering](rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.kql) | high | stealth, defense-impairment, T1564.001, T1112, persistence | DeviceRegistryEvents |
| [Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG](rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.kql) | high | stealth, T1218 | DeviceRegistryEvents |
| [Suspicious Execution Of Renamed Sysinternals Tools - Registry](rules/windows/registry/registry_set/registry_set_pua_sysinternals_renamed_execution_via_eula.kql) | high | resource-development, T1588.002 | DeviceRegistryEvents |
| [PUA - Sysinternals Tools Execution - Registry](rules/windows/registry/registry_set/registry_set_pua_sysinternals_susp_execution_via_eula.kql) | medium | resource-development, T1588.002 | DeviceRegistryEvents |
| [Usage of Renamed Sysinternals Tools - RegistrySet](rules/windows/registry/registry_set/registry_set_renamed_sysinternals_eula_accepted.kql) | high | resource-development, T1588.002 | DeviceRegistryEvents |
| [Potentially Suspicious Command Executed Via Run Dialog Box - Registry](rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.kql) | high | execution, T1059.001 | DeviceRegistryEvents |
| [ScreenSaver Registry Key Set](rules/windows/registry/registry_set/registry_set_scr_file_executed_by_rundll32.kql) | medium | stealth, T1218.011 | DeviceRegistryEvents |
| [Potential SentinelOne Shell Context Menu Scan Command Tampering](rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.kql) | medium | persistence | DeviceRegistryEvents |
| [ServiceDll Hijack](rules/windows/registry/registry_set/registry_set_servicedll_hijack.kql) | medium | persistence, privilege-escalation, T1543.003 | DeviceRegistryEvents |
| [Persistence Via New SIP Provider](rules/windows/registry/registry_set/registry_set_sip_persistence.kql) | medium | persistence, defense-impairment, T1553.003 | DeviceRegistryEvents |
| [Tamper With Sophos AV Registry Keys](rules/windows/registry/registry_set/registry_set_sophos_av_tamper.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Hiding User Account Via SpecialAccounts Registry Key](rules/windows/registry/registry_set/registry_set_special_accounts.kql) | high | stealth, T1564.002 | DeviceRegistryEvents |
| [Activate Suppression of Windows Security Center Notifications](rules/windows/registry/registry_set/registry_set_suppress_defender_notifications.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Suspicious Keyboard Layout Load](rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.kql) | medium | resource-development, T1588.002 | DeviceRegistryEvents |
| [Potential PendingFileRenameOperations Tampering](rules/windows/registry/registry_set/registry_set_susp_pendingfilerenameoperations.kql) | medium | stealth, T1036.003 | DeviceRegistryEvents |
| [Suspicious Printer Driver Empty Manufacturer](rules/windows/registry/registry_set/registry_set_susp_printer_driver.kql) | high | persistence, privilege-escalation, execution, stealth, T1574 | DeviceRegistryEvents |
| [Registry Persistence via Explorer Run Key](rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Suspicious Service Installed](rules/windows/registry/registry_set/registry_set_susp_service_installed.kql) | medium | defense-impairment, T1685 | DeviceRegistryEvents |
| [Modify User Shell Folders Startup Value](rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.kql) | high | persistence, privilege-escalation, T1547.001 | DeviceRegistryEvents |
| [Suspicious Environment Variable Has Been Registered](rules/windows/registry/registry_set/registry_set_suspicious_env_variables.kql) | high | persistence, stealth | DeviceRegistryEvents |
| [Enable LM Hash Storage](rules/windows/registry/registry_set/registry_set_system_lsa_nolmhash.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Scheduled TaskCache Change by Uncommon Program](rules/windows/registry/registry_set/registry_set_taskcache_entry.kql) | high | privilege-escalation, execution, persistence, T1053, T1053.005 | DeviceRegistryEvents |
| [Potential Registry Persistence Attempt Via Windows Telemetry](rules/windows/registry/registry_set/registry_set_telemetry_persistence.kql) | high | privilege-escalation, execution, persistence, T1053.005 | DeviceRegistryEvents |
| [RDP Sensitive Settings Changed to Zero](rules/windows/registry/registry_set/registry_set_terminal_server_suspicious.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [RDP Sensitive Settings Changed](rules/windows/registry/registry_set/registry_set_terminal_server_tampering.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [New TimeProviders Registered With Uncommon DLL Name](rules/windows/registry/registry_set/registry_set_timeproviders_dllname.kql) | high | persistence, privilege-escalation, T1547.003 | DeviceRegistryEvents |
| [Old TLS1.0/TLS1.1 Protocol Version Enabled](rules/windows/registry/registry_set/registry_set_tls_protocol_old_version_enabled.kql) | medium | stealth | DeviceRegistryEvents |
| [COM Hijacking via TreatAs](rules/windows/registry/registry_set/registry_set_treatas_persistence.kql) | medium | privilege-escalation, persistence, T1546.015 | DeviceRegistryEvents |
| [Potential Signing Bypass Via Windows Developer Features - Registry](rules/windows/registry/registry_set/registry_set_turn_on_dev_features.kql) | high | stealth | DeviceRegistryEvents |
| [UAC Bypass via Event Viewer](rules/windows/registry/registry_set/registry_set_uac_bypass_eventvwr.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [UAC Bypass via Sdclt](rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [UAC Bypass Abusing Winsat Path Parsing - Registry](rules/windows/registry/registry_set/registry_set_uac_bypass_winsat.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [UAC Bypass Using Windows Media Player - Registry](rules/windows/registry/registry_set/registry_set_uac_bypass_wmp.kql) | high | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [UAC Disabled](rules/windows/registry/registry_set/registry_set_uac_disable.kql) | medium | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [UAC Notification Disabled](rules/windows/registry/registry_set/registry_set_uac_disable_notification.kql) | medium | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [UAC Secure Desktop Prompt Disabled](rules/windows/registry/registry_set/registry_set_uac_disable_secure_desktop_prompt.kql) | medium | privilege-escalation, T1548.002 | DeviceRegistryEvents |
| [VBScript Payload Stored in Registry](rules/windows/registry/registry_set/registry_set_vbs_payload_stored.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Execution DLL of Choice Using WAB.EXE](rules/windows/registry/registry_set/registry_set_wab_dllpath_reg_change.kql) | high | stealth, T1218 | DeviceRegistryEvents |
| [Wdigest Enable UseLogonCredential](rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Disable Windows Defender Functionalities Via Registry Keys](rules/windows/registry/registry_set/registry_set_windows_defender_tamper.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Enable Local Manifest Installation With Winget](rules/windows/registry/registry_set/registry_set_winget_enable_local_manifest.kql) | medium | persistence, stealth | DeviceRegistryEvents |
| [Winlogon AllowMultipleTSSessions Enable](rules/windows/registry/registry_set/registry_set_winlogon_allow_multiple_tssessions.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Winlogon Notify Key Logon Persistence](rules/windows/registry/registry_set/registry_set_winlogon_notify_key.kql) | high | privilege-escalation, persistence, T1547.004 | DeviceRegistryEvents |

## rules-emerging-threats (230)

| Rule | Level | ATT&CK | Table |
|---|---|---|---|
| [ZxShell Malware](rules-emerging-threats/2014/TA/Axiom/proc_creation_win_apt_zxshell.kql) | critical | execution, stealth, T1059.003, T1218.011, S0412, G0001 | DeviceProcessEvents |
| [Turla Group Lateral Movement](rules-emerging-threats/2014/TA/Turla/proc_creation_win_apt_turla_commands_critical.kql) | critical | G0010, execution, T1059, lateral-movement, T1021.002, discovery, T1083, T1135 | DeviceProcessEvents |
| [Turla Group Commands May 2020](rules-emerging-threats/2014/TA/Turla/proc_creation_win_apt_turla_comrat_may20.kql) | critical | privilege-escalation, persistence, stealth, G0010, execution, T1059.001, T1053.005, T1027 | DeviceProcessEvents |
| [Exploit for CVE-2015-1641](rules-emerging-threats/2015/Exploits/CVE-2015-1641/proc_creation_win_exploit_cve_2015_1641.kql) | critical | stealth, T1036.005 | DeviceProcessEvents |
| [Exploit for CVE-2017-0261](rules-emerging-threats/2017/Exploits/CVE-2017-0261/proc_creation_win_exploit_cve_2017_0261.kql) | medium | execution, T1203, T1204.002, initial-access, T1566.001 | DeviceProcessEvents |
| [Droppers Exploiting CVE-2017-11882](rules-emerging-threats/2017/Exploits/CVE-2017-11882/proc_creation_win_exploit_cve_2017_11882.kql) | critical | execution, T1203, T1204.002, initial-access, T1566.001 | DeviceProcessEvents |
| [Exploit for CVE-2017-8759](rules-emerging-threats/2017/Exploits/CVE-2017-8759/proc_creation_win_exploit_cve_2017_8759.kql) | critical | execution, T1203, T1204.002, initial-access, T1566.001 | DeviceProcessEvents |
| [Adwind RAT / JRAT](rules-emerging-threats/2017/Malware/Adwind-RAT/proc_creation_win_malware_adwind.kql) | high | execution, T1059.005, T1059.007 | DeviceProcessEvents |
| [Fireball Archer Install](rules-emerging-threats/2017/Malware/Fireball/proc_creation_win_malware_fireball.kql) | high | execution, stealth, T1218.011 | DeviceProcessEvents |
| [Potential PlugX Activity](rules-emerging-threats/2017/Malware/PlugX/proc_creation_win_malware_plugx_susp_exe_locations.kql) | high | privilege-escalation, persistence, execution, stealth, S0013, T1574.001 | DeviceProcessEvents |
| [WannaCry Ransomware Activity](rules-emerging-threats/2017/Malware/WannaCry/proc_creation_win_malware_wannacry.kql) | critical | lateral-movement, defense-impairment, T1210, discovery, T1083, T1222.001, impact, T1486, T1490 | DeviceProcessEvents |
| [Potential APT10 Cloud Hopper Activity](rules-emerging-threats/2017/TA/APT10/proc_creation_win_apt_apt10_cloud_hopper.kql) | high | execution, G0045, T1059.005 | DeviceProcessEvents |
| [Ps.exe Renamed SysInternals Tool](rules-emerging-threats/2017/TA/Dragonfly/proc_creation_win_apt_ta17_293a_ps.kql) | high | stealth, G0035, T1036.003 | DeviceProcessEvents |
| [Lazarus System Binary Masquerading](rules-emerging-threats/2017/TA/Lazarus/proc_creation_win_apt_lazarus_binary_masquerading.kql) | high | stealth, T1036.005 | DeviceProcessEvents |
| [Pandemic Registry Key](rules-emerging-threats/2017/TA/Pandemic/registry_event_apt_pandemic.kql) | critical | command-and-control, T1105 | DeviceRegistryEvents |
| [Elise Backdoor Activity](rules-emerging-threats/2018/Malware/Elise-Backdoor/proc_creation_win_malware_elise.kql) | critical | G0030, G0050, S0081, execution, T1059.003 | DeviceProcessEvents |
| [APT27 - Emissary Panda Activity](rules-emerging-threats/2018/TA/APT27/proc_creation_win_apt_apt27_emissary_panda.kql) | critical | privilege-escalation, persistence, execution, stealth, T1574.001, G0027 | DeviceProcessEvents |
| [Sofacy Trojan Loader Activity](rules-emerging-threats/2018/TA/APT28/proc_creation_win_apt_sofacy.kql) | high | execution, stealth, G0007, T1059.003, T1218.011 | DeviceProcessEvents |
| [APT29 2018 Phishing Campaign File Indicators](rules-emerging-threats/2018/TA/APT29-CozyBear/file_event_win_apt_cozy_bear_phishing_campaign_indicators.kql) | critical | stealth, T1218.011 | DeviceFileEvents |
| [APT29 2018 Phishing Campaign CommandLine Indicators](rules-emerging-threats/2018/TA/APT29-CozyBear/proc_creation_win_apt_apt29_phishing_campaign_indicators.kql) | critical | execution, stealth, T1218.011 | DeviceProcessEvents |
| [OceanLotus Registry Activity](rules-emerging-threats/2018/TA/APT32-Oceanlotus/registry_event_apt_oceanlotus_registry.kql) | critical | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential MuddyWater APT Activity](rules-emerging-threats/2018/TA/MuddyWater/proc_creation_win_apt_muddywater_activity.kql) | high | execution, stealth, G0069 | DeviceProcessEvents |
| [OilRig APT Activity](rules-emerging-threats/2018/TA/OilRig/proc_creation_win_apt_oilrig_mar18.kql) | critical | privilege-escalation, execution, persistence, defense-impairment, G0049, T1053.005, S0111, T1543.003, T1112, command-and-control, T1071.004 | DeviceProcessEvents |
| [OilRig APT Registry Persistence](rules-emerging-threats/2018/TA/OilRig/registry_event_apt_oilrig_mar18.kql) | critical | privilege-escalation, execution, persistence, defense-impairment, G0049, T1053.005, S0111, T1543.003, T1112, command-and-control, T1071.004 | DeviceRegistryEvents |
| [Defrag Deactivation](rules-emerging-threats/2018/TA/Slingshot/proc_creation_win_apt_slingshot.kql) | medium | privilege-escalation, execution, persistence, T1053.005, S0111 | DeviceProcessEvents |
| [TropicTrooper Campaign November 2018](rules-emerging-threats/2018/TA/TropicTrooper/proc_creation_win_apt_tropictrooper.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Potential BearLPE Exploitation](rules-emerging-threats/2019/Exploits/BearLPE-Exploit/proc_creation_win_exploit_other_bearlpe.kql) | high | persistence, execution, privilege-escalation, T1053.005 | DeviceProcessEvents |
| [Exploiting SetupComplete.cmd CVE-2019-1378](rules-emerging-threats/2019/Exploits/CVE-2019-1378/proc_creation_win_exploit_cve_2019_1378.kql) | high | persistence, privilege-escalation, stealth, T1068, execution, T1059.003, T1574 | DeviceProcessEvents |
| [Exploiting CVE-2019-1388](rules-emerging-threats/2019/Exploits/CVE-2019-1388/proc_creation_win_exploit_cve_2019_1388.kql) | critical | privilege-escalation, T1068 | DeviceProcessEvents |
| [Sudo Privilege Escalation CVE-2019-14287](rules-emerging-threats/2019/Exploits/CVE-2019-14287/proc_creation_lnx_exploit_cve_2019_14287.kql) | high | privilege-escalation, T1068, T1548.003 | DeviceProcessEvents |
| [Potential Baby Shark Malware Activity](rules-emerging-threats/2019/Malware/BabyShark/proc_creation_win_malware_babyshark.kql) | high | execution, discovery, stealth, T1012, T1059.003, T1059.001, T1218.005 | DeviceProcessEvents |
| [Potential Dridex Activity](rules-emerging-threats/2019/Malware/Dridex/proc_creation_win_malware_dridex.kql) | critical | privilege-escalation, stealth, T1055, discovery, T1135, T1033 | DeviceProcessEvents |
| [Potential Dtrack RAT Activity](rules-emerging-threats/2019/Malware/Dtrack-RAT/proc_creation_win_malware_dtrack.kql) | critical | impact, T1490 | DeviceProcessEvents |
| [Potential Emotet Activity](rules-emerging-threats/2019/Malware/Emotet/proc_creation_win_malware_emotet.kql) | high | execution, stealth, T1059.001, T1027 | DeviceProcessEvents |
| [Formbook Process Creation](rules-emerging-threats/2019/Malware/Formbook/proc_creation_win_malware_formbook.kql) | high | resource-development, T1587.001 | DeviceProcessEvents |
| [LockerGoga Ransomware Activity](rules-emerging-threats/2019/Malware/LockerGoga/proc_creation_win_malware_lockergoga_ransomware.kql) | critical | impact, T1486 | DeviceProcessEvents |
| [Potential QBot Activity](rules-emerging-threats/2019/Malware/QBot/proc_creation_win_malware_qbot.kql) | critical | execution, T1059.005 | DeviceProcessEvents |
| [Potential Ryuk Ransomware Activity](rules-emerging-threats/2019/Malware/Ryuk/proc_creation_win_malware_ryuk.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceProcessEvents |
| [Potential Snatch Ransomware Activity](rules-emerging-threats/2019/Malware/Snatch/proc_creation_win_malware_snatch_ransomware.kql) | high | execution, T1204 | DeviceProcessEvents |
| [Potential Ursnif Malware Activity - Registry](rules-emerging-threats/2019/Malware/Ursnif/registry_add_malware_ursnif.kql) | high | persistence, execution, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential APT-C-12 BlueMushroom DLL Load Activity Via Regsvr32](rules-emerging-threats/2019/TA/APC-C-12/proc_creation_win_apt_aptc12_bluemushroom.kql) | medium | stealth, T1218.010 | DeviceProcessEvents |
| [APT31 Judgement Panda Activity](rules-emerging-threats/2019/TA/APT31/proc_creation_win_apt_apt31_judgement_panda.kql) | critical | collection, lateral-movement, credential-access, G0128, T1003.001, T1560.001 | DeviceProcessEvents |
| [Potential Russian APT Credential Theft Activity](rules-emerging-threats/2019/TA/Bear-APT-Activity/proc_creation_win_apt_bear_activity_gtr19.kql) | critical | credential-access, T1552.001, T1003.003 | DeviceProcessEvents |
| [Potential EmpireMonkey Activity](rules-emerging-threats/2019/TA/EmpireMonkey/proc_creation_win_apt_empiremonkey.kql) | high | stealth, T1218.010 | DeviceProcessEvents |
| [Equation Group DLL_U Export Function Load](rules-emerging-threats/2019/TA/EquationGroup/proc_creation_win_apt_equationgroup_dll_u_load.kql) | critical | stealth, G0020, T1218.011 | DeviceProcessEvents |
| [Mustang Panda Dropper](rules-emerging-threats/2019/TA/MustangPanda/proc_creation_win_apt_mustangpanda.kql) | high | T1587.001, resource-development | DeviceProcessEvents |
| [Operation Wocao Activity](rules-emerging-threats/2019/TA/Operation-Wocao/proc_creation_win_apt_wocao.kql) | high | privilege-escalation, persistence, discovery, stealth, T1012, T1036.004, T1027, execution, T1053.005, T1059.001 | DeviceProcessEvents |
| [Exploited CVE-2020-10189 Zoho ManageEngine](rules-emerging-threats/2020/Exploits/CVE-2020-10189/proc_creation_win_exploit_cve_2020_10189.kql) | high | initial-access, T1190, execution, T1059.001, T1059.003, S0190 | DeviceProcessEvents |
| [Suspicious PrinterPorts Creation (CVE-2020-1048)](rules-emerging-threats/2020/Exploits/CVE-2020-1048/proc_creation_win_exploit_cve_2020_1048.kql) | high | persistence, execution, T1059.001 | DeviceProcessEvents |
| [CVE-2020-1048 Exploitation Attempt - Suspicious New Printer Ports - Registry](rules-emerging-threats/2020/Exploits/CVE-2020-1048/registry_set_exploit_cve_2020_1048_new_printer_port.kql) | high | persistence, execution, defense-impairment, T1112 | DeviceRegistryEvents |
| [DNS RCE CVE-2020-1350](rules-emerging-threats/2020/Exploits/CVE-2020-1350/proc_creation_win_exploit_cve_2020_1350.kql) | critical | initial-access, T1190, execution, T1569.002 | DeviceProcessEvents |
| [Exploitation Attempt Of CVE-2020-1472 - Execution of ZeroLogon PoC](rules-emerging-threats/2020/Exploits/CVE-2020-1472/proc_creation_win_exploit_cve_2020_1472_zero_poc.kql) | high | execution, lateral-movement, T1210 | DeviceProcessEvents |
| [Blue Mockingbird](rules-emerging-threats/2020/Malware/Blue-Mockingbird/proc_creation_win_malware_blue_mockingbird.kql) | high | persistence, execution, defense-impairment, T1112, T1047 | DeviceProcessEvents |
| [Blue Mockingbird - Registry](rules-emerging-threats/2020/Malware/Blue-Mockingbird/registry_set_mal_blue_mockingbird.kql) | high | execution, persistence, defense-impairment, T1112, T1047 | DeviceRegistryEvents |
| [Potential Emotet Rundll32 Execution](rules-emerging-threats/2020/Malware/Emotet/proc_creation_win_malware_emotet_rundll32_execution.kql) | critical | stealth, T1218.011 | DeviceProcessEvents |
| [FlowCloud Registry Markers](rules-emerging-threats/2020/Malware/FlowCloud/registry_event_malware_flowcloud_markers.kql) | critical | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Potential Ke3chang/TidePool Malware Activity](rules-emerging-threats/2020/Malware/Ke3chang-TidePool/proc_creation_win_malware_ke3chang_tidepool.kql) | high | defense-impairment, G0004, T1685 | DeviceProcessEvents |
| [Potential Maze Ransomware Activity](rules-emerging-threats/2020/Malware/Maze/proc_creation_win_malware_maze_ransomware.kql) | critical | execution, T1204.002, T1047, impact, T1490 | DeviceProcessEvents |
| [Trickbot Malware Activity](rules-emerging-threats/2020/Malware/Trickbot/proc_creation_win_malware_trickbot_wermgr.kql) | high | execution, T1559 | DeviceProcessEvents |
| [EvilNum APT Golden Chickens Deployment Via OCX Files](rules-emerging-threats/2020/TA/Evilnum/proc_creation_win_apt_evilnum_jul20.kql) | critical | stealth, T1218.011 | DeviceProcessEvents |
| [GALLIUM IOCs](rules-emerging-threats/2020/TA/GALLIUM/proc_creation_win_apt_gallium_iocs.kql) | high | credential-access, command-and-control, T1212, T1071, G0093 | DeviceProcessEvents |
| [Greenbug Espionage Group Indicators](rules-emerging-threats/2020/TA/Greenbug/proc_creation_win_apt_greenbug_may20.kql) | critical | stealth, G0049, execution, T1059.001, command-and-control, T1105, T1036.005 | DeviceProcessEvents |
| [Lazarus Group Activity](rules-emerging-threats/2020/TA/Lazarus/proc_creation_win_apt_lazarus_group_activity.kql) | critical | G0032, execution, T1059 | DeviceProcessEvents |
| [Leviathan Registry Key Activity](rules-emerging-threats/2020/TA/Leviathan/registry_event_apt_leviathan.kql) | critical | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [UNC2452 Process Creation Patterns](rules-emerging-threats/2020/TA/SolarWinds-Supply-Chain/proc_creation_win_apt_unc2452_cmds.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [UNC2452 PowerShell Pattern](rules-emerging-threats/2020/TA/SolarWinds-Supply-Chain/proc_creation_win_apt_unc2452_ps.kql) | critical | execution, T1059.001, T1047 | DeviceProcessEvents |
| [Suspicious VBScript UN2452 Pattern](rules-emerging-threats/2020/TA/SolarWinds-Supply-Chain/proc_creation_win_apt_unc2452_vbscript_pattern.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceProcessEvents |
| [TAIDOOR RAT DLL Load](rules-emerging-threats/2020/TA/TAIDOOR-RAT/proc_creation_win_apt_taidoor.kql) | high | privilege-escalation, execution, stealth, T1055.001 | DeviceProcessEvents |
| [Winnti Malware HK University Campaign](rules-emerging-threats/2020/TA/Winnti/proc_creation_win_apt_winnti_mal_hk_jan20.kql) | critical | privilege-escalation, persistence, execution, stealth, T1574.001, G0044 | DeviceProcessEvents |
| [Winnti Pipemon Characteristics](rules-emerging-threats/2020/TA/Winnti/proc_creation_win_apt_winnti_pipemon.kql) | critical | privilege-escalation, persistence, execution, stealth, T1574.001, G0044 | DeviceProcessEvents |
| [Potential PrintNightmare Exploitation Attempt](rules-emerging-threats/2021/Exploits/CVE-2021-1675/file_delete_win_exploit_cve_2021_1675_print_nightmare.kql) | high | persistence, privilege-escalation, execution, stealth, T1574 | DeviceFileEvents |
| [CVE-2021-1675 Print Spooler Exploitation Filename Pattern](rules-emerging-threats/2021/Exploits/CVE-2021-1675/file_event_win_exploit_cve_2021_1675_printspooler.kql) | critical | execution, privilege-escalation, resource-development, T1587 | DeviceFileEvents |
| [PrinterNightmare Mimikatz Driver Name](rules-emerging-threats/2021/Exploits/CVE-2021-1675/registry_event_cve_2021_1675_mimikatz_printernightmare_drivers.kql) | critical | execution, T1204 | DeviceRegistryEvents |
| [Potential Atlassian Confluence CVE-2021-26084 Exploitation Attempt](rules-emerging-threats/2021/Exploits/CVE-2021-26084/proc_creation_win_exploit_cve_2021_26084_atlassian_confluence.kql) | high | initial-access, execution, T1190, T1059 | DeviceProcessEvents |
| [Potential CVE-2021-26857 Exploitation Attempt](rules-emerging-threats/2021/Exploits/CVE-2021-26857/proc_creation_win_exploit_cve_2021_26857_msexchange.kql) | high | T1203, execution | DeviceProcessEvents |
| [CVE-2021-26858 Exchange Exploitation](rules-emerging-threats/2021/Exploits/CVE-2021-26858/file_event_win_cve_2021_26858_msexchange.kql) | high | T1203, execution | DeviceFileEvents |
| [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](rules-emerging-threats/2021/Exploits/CVE-2021-33771/file_event_win_cve_2021_31979_cve_2021_33771_exploits.kql) | critical | initial-access, execution, credential-access, T1566, T1203 | DeviceFileEvents |
| [CVE-2021-31979 CVE-2021-33771 Exploits](rules-emerging-threats/2021/Exploits/CVE-2021-33771/registry_set_cve_2021_31979_cve_2021_33771_exploits.kql) | critical | initial-access, execution, credential-access, T1566, T1203 | DeviceRegistryEvents |
| [Serv-U Exploitation CVE-2021-35211 by DEV-0322](rules-emerging-threats/2021/Exploits/CVE-2021-35211/proc_creation_win_exploit_cve_2021_35211_servu.kql) | critical | persistence, T1136.001 | DeviceProcessEvents |
| [Suspicious Word Cab File Write CVE-2021-40444](rules-emerging-threats/2021/Exploits/CVE-2021-40444/file_event_win_exploit_cve_2021_40444.kql) | high | resource-development, T1587 | DeviceFileEvents |
| [Potential CVE-2021-40444 Exploitation Attempt](rules-emerging-threats/2021/Exploits/CVE-2021-40444/proc_creation_win_exploit_cve_2021_40444.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Potential Exploitation Attempt From Office Application](rules-emerging-threats/2021/Exploits/CVE-2021-40444/proc_creation_win_exploit_cve_2021_40444_office_directory_traversal.kql) | high | execution, stealth | DeviceProcessEvents |
| [InstallerFileTakeOver LPE CVE-2021-41379 File Create Event](rules-emerging-threats/2021/Exploits/CVE-2021-41379/file_event_win_cve_2021_41379_msi_lpe.kql) | critical | privilege-escalation, T1068 | DeviceFileEvents |
| [Potential CVE-2021-41379 Exploitation Attempt](rules-emerging-threats/2021/Exploits/CVE-2021-41379/proc_creation_win_exploit_cve_2021_41379.kql) | critical | privilege-escalation, T1068 | DeviceProcessEvents |
| [CVE-2021-44077 POC Default Dropped File](rules-emerging-threats/2021/Exploits/CVE-2021-44077/file_event_win_cve_2021_44077_poc_default_files.kql) | high | execution | DeviceFileEvents |
| [Potential CVE-2021-44228 Exploitation Attempt - VMware Horizon](rules-emerging-threats/2021/Exploits/CVE-2021-44228/proc_creation_win_exploit_cve_2021_44228_vmware_horizon_log4j.kql) | high | initial-access, T1190 | DeviceProcessEvents |
| [Suspicious RazerInstaller Explorer Subprocess](rules-emerging-threats/2021/Exploits/RazerInstaller-LPE-Exploit/proc_creation_win_exploit_other_razorinstaller_lpe.kql) | high | privilege-escalation, defense-impairment, T1553 | DeviceProcessEvents |
| [Potential SystemNightmare Exploitation Attempt](rules-emerging-threats/2021/Exploits/SystemNightmare-Exploit/proc_creation_win_exploit_other_systemnightmare.kql) | critical | privilege-escalation, T1068 | DeviceProcessEvents |
| [Potential BlackByte Ransomware Activity](rules-emerging-threats/2021/Malware/BlackByte/proc_creation_win_malware_blackbyte_ransomware.kql) | high | execution, impact, stealth, T1485, T1498, T1059.001, T1140 | DeviceProcessEvents |
| [Blackbyte Ransomware Registry](rules-emerging-threats/2021/Malware/BlackByte/registry_set_win_malware_blackbyte_privesc_registry.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Conti Volume Shadow Listing](rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti.kql) | high | T1587.001, resource-development | DeviceProcessEvents |
| [Conti NTDS Exfiltration Command](rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti_7zip.kql) | high | collection, T1560 | DeviceProcessEvents |
| [Potential Conti Ransomware Activity](rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti_ransomware_commands.kql) | critical | impact, S0575, T1486 | DeviceProcessEvents |
| [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti_ransomware_database_dump.kql) | high | collection, T1005 | DeviceProcessEvents |
| [DarkSide Ransomware Pattern](rules-emerging-threats/2021/Malware/DarkSide/proc_creation_win_malware_darkside_ransomware.kql) | critical | execution, T1204 | DeviceProcessEvents |
| [Potential Devil Bait Related Indicator](rules-emerging-threats/2021/Malware/Devil-Bait/file_event_win_malware_devil_bait_script_drop.kql) | high | stealth | DeviceFileEvents |
| [Potential Devil Bait Malware Reconnaissance](rules-emerging-threats/2021/Malware/Devil-Bait/proc_creation_win_malware_devil_bait_output_redirect.kql) | high | stealth, T1218 | DeviceProcessEvents |
| [FoggyWeb Backdoor DLL Loading](rules-emerging-threats/2021/Malware/FoggyWeb/image_load_malware_foggyweb_nobelium.kql) | critical | resource-development, T1587 | DeviceImageLoadEvents |
| [Goofy Guineapig Backdoor IOC](rules-emerging-threats/2021/Malware/Goofy-Guineapig/file_event_win_malware_goofy_guineapig_file_indicators.kql) | high | execution, stealth | DeviceFileEvents |
| [Potential Goofy Guineapig Backdoor Activity](rules-emerging-threats/2021/Malware/Goofy-Guineapig/proc_creation_win_malware_goofy_guineapig_broken_cmd.kql) | high | execution | DeviceProcessEvents |
| [Potential Goofy Guineapig GoolgeUpdate Process Anomaly](rules-emerging-threats/2021/Malware/Goofy-Guineapig/proc_creation_win_malware_goofy_guineapig_googleupdate_uncommon_child_instance.kql) | high | stealth | DeviceProcessEvents |
| [Moriya Rootkit File Created](rules-emerging-threats/2021/Malware/Moriya-Rootkit/file_event_win_moriya_rootkit.kql) | critical | persistence, privilege-escalation, T1543.003 | DeviceFileEvents |
| [Potential NetWire RAT Activity - Registry](rules-emerging-threats/2021/Malware/Netwire/registry_add_malware_netwire.kql) | high | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Pingback Backdoor File Indicators](rules-emerging-threats/2021/Malware/Pingback/file_event_win_malware_pingback_backdoor.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceFileEvents |
| [Pingback Backdoor DLL Loading Activity](rules-emerging-threats/2021/Malware/Pingback/image_load_malware_pingback_backdoor.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Pingback Backdoor Activity](rules-emerging-threats/2021/Malware/Pingback/proc_creation_win_malware_pingback_backdoor.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Small Sieve Malware File Indicator Creation](rules-emerging-threats/2021/Malware/Small-Sieve/file_event_win_malware_small_sieve_evasion_typo.kql) | high | stealth, T1036.005 | DeviceFileEvents |
| [Small Sieve Malware CommandLine Indicator](rules-emerging-threats/2021/Malware/Small-Sieve/proc_creation_win_malware_small_sieve_cli_arg.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001 | DeviceProcessEvents |
| [Small Sieve Malware Registry Persistence](rules-emerging-threats/2021/Malware/Small-Sieve/registry_set_malware_small_sieve_evasion_typo.kql) | high | persistence | DeviceRegistryEvents |
| [HAFNIUM Exchange Exploitation Activity](rules-emerging-threats/2021/TA/HAFNIUM/proc_creation_win_apt_hafnium.kql) | critical | privilege-escalation, execution, persistence, T1546, T1053, G0125 | DeviceProcessEvents |
| [REvil Kaseya Incident Malware Patterns](rules-emerging-threats/2021/TA/Kaseya-Supply-Chain/proc_creation_win_apt_revil_kaseya.kql) | critical | execution, T1059, G0115 | DeviceProcessEvents |
| [APT PRIVATELOG Image Load Pattern](rules-emerging-threats/2021/TA/PRIVATELOG/image_load_usp_svchost_clfsw32.kql) | high | privilege-escalation, stealth, T1055 | DeviceImageLoadEvents |
| [SOURGUM Actor Behaviours](rules-emerging-threats/2021/TA/SOURGUM/proc_creation_win_apt_sourgrum.kql) | high | T1546, T1546.015, persistence, privilege-escalation | DeviceProcessEvents |
| [Potential CVE-2023-21554 QueueJumper Exploitation](rules-emerging-threats/2022/Exploits/CVE-2022-21554/proc_creation_win_exploit_cve_2023_21554_queuejumper.kql) | high | privilege-escalation, execution | DeviceProcessEvents |
| [Potential CVE-2022-22954 Exploitation Attempt - VMware Workspace ONE Access Remote Code Execution](rules-emerging-threats/2022/Exploits/CVE-2022-22954/proc_creation_win_exploit_cve_2022_22954_vmware_workspace_one_rce.kql) | medium | execution, initial-access, T1059.006, T1190 | DeviceProcessEvents |
| [CVE-2022-24527 Microsoft Connected Cache LPE](rules-emerging-threats/2022/Exploits/CVE-2022-24527/file_event_win_cve_2022_24527_lpe.kql) | high | execution, privilege-escalation, T1059.001 | DeviceFileEvents |
| [Atlassian Confluence CVE-2022-26134](rules-emerging-threats/2022/Exploits/CVE-2022-26134/proc_creation_lnx_exploit_cve_2022_26134_atlassian_confluence.kql) | high | initial-access, execution, T1190, T1059 | DeviceProcessEvents |
| [Potential CVE-2022-26809 Exploitation Attempt](rules-emerging-threats/2022/Exploits/CVE-2022-26809/proc_creation_win_exploit_cve_2022_26809_rpcss_child_process_anomaly.kql) | high | initial-access, T1190, execution, T1569.002 | DeviceProcessEvents |
| [Potential CVE-2022-29072 Exploitation Attempt](rules-emerging-threats/2022/Exploits/CVE-2022-29072/proc_creation_win_exploit_cve_2022_29072_7zip.kql) | high | execution | DeviceProcessEvents |
| [Suspicious Set Value of MSDT in Registry (CVE-2022-30190)](rules-emerging-threats/2022/Exploits/CVE-2022-30190/registry_set_exploit_cve_2022_30190_msdt_follina.kql) | medium | stealth, T1221 | DeviceRegistryEvents |
| [Apache Spark Shell Command Injection - ProcessCreation](rules-emerging-threats/2022/Exploits/CVE-2022-33891/proc_creation_lnx_exploit_cve_2022_33891_spark_shell_command_injection.kql) | high | initial-access, T1190 | DeviceProcessEvents |
| [Suspicious Sysmon as Execution Parent](rules-emerging-threats/2022/Exploits/CVE-2022-41120/proc_creation_win_exploit_cve_2022_41120_sysmon_eop.kql) | high | privilege-escalation, T1068 | DeviceProcessEvents |
| [ChromeLoader Malware Execution](rules-emerging-threats/2022/Malware/ChromeLoader/proc_creation_win_malware_chrome_loader_execution.kql) | high | privilege-escalation, execution, persistence, T1053.005, T1059.001, T1176 | DeviceProcessEvents |
| [Emotet Loader Execution Via .LNK File](rules-emerging-threats/2022/Malware/Emotet/proc_creation_win_malware_emotet_loader_execution.kql) | high | execution, T1059.006 | DeviceProcessEvents |
| [Hermetic Wiper TG Process Patterns](rules-emerging-threats/2022/Malware/Hermetic-Wiper/proc_creation_win_malware_hermetic_wiper_activity.kql) | high | execution, lateral-movement, T1021.001 | DeviceProcessEvents |
| [Raspberry Robin Subsequent Execution of Commands](rules-emerging-threats/2022/Malware/Raspberry-Robin/proc_creation_win_malware_raspberry_robin_execution.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Raspberry Robin Initial Execution From External Drive](rules-emerging-threats/2022/Malware/Raspberry-Robin/proc_creation_win_malware_raspberry_robin_external_drive_exec.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Potential Raspberry Robin Dot Ending File](rules-emerging-threats/2022/Malware/Raspberry-Robin/proc_creation_win_malware_raspberry_robin_single_dot_ending_file.kql) | high | execution | DeviceProcessEvents |
| [Serpent Backdoor Payload Execution Via Scheduled Task](rules-emerging-threats/2022/Malware/Serpent-Backdoor/proc_creation_win_malware_serpent_backdoor_payload_execution.kql) | high | privilege-escalation, execution, persistence, T1053.005, T1059.006 | DeviceProcessEvents |
| [FakeUpdates/SocGholish Activity](rules-emerging-threats/2022/Malware/SocGholish/proc_creation_win_malware_socgholish_fakeupdates_activity.kql) | high | execution, T1059.001 | DeviceProcessEvents |
| [Potential ACTINIUM Persistence Activity](rules-emerging-threats/2022/TA/ACTINIUM/proc_creation_win_apt_actinium_persistence.kql) | high | privilege-escalation, execution, persistence, T1053, T1053.005 | DeviceProcessEvents |
| [MERCURY APT Activity](rules-emerging-threats/2022/TA/MERCURY/proc_creation_win_apt_mercury.kql) | high | execution, T1059.001, G0069 | DeviceProcessEvents |
| [CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Linux)](rules-emerging-threats/2023/Exploits/CVE-2023-22518/proc_creation_lnx_exploit_cve_2023_22518_confluence_java_child_proc.kql) | high | execution, T1059, initial-access, T1190 | DeviceProcessEvents |
| [CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Windows)](rules-emerging-threats/2023/Exploits/CVE-2023-22518/proc_creation_win_exploit_cve_2023_22518_confluence_tomcat_child_proc.kql) | medium | execution, T1059, initial-access, T1190 | DeviceProcessEvents |
| [Potential CVE-2023-27363 Exploitation - HTA File Creation By FoxitPDFReader](rules-emerging-threats/2023/Exploits/CVE-2023-27363/file_event_win_cve_2023_27363_foxit_rce.kql) | high | persistence, T1505.001 | DeviceFileEvents |
| [Potential MOVEit Transfer CVE-2023-34362 Exploitation - Dynamic Compilation Via Csc.EXE](rules-emerging-threats/2023/Exploits/CVE-2023-34362-MOVEit-Transfer-Exploit/proc_creation_win_exploit_cve_2023_34362_moveit_transfer_exploitation_activity.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Potential CVE-2023-36874 Exploitation - Uncommon Report.Wer Location](rules-emerging-threats/2023/Exploits/CVE-2023-36874/file_event_win_exploit_cve_2023_36874_report_creation.kql) | medium | execution | DeviceFileEvents |
| [Potential CVE-2023-36874 Exploitation - Fake Wermgr.Exe Creation](rules-emerging-threats/2023/Exploits/CVE-2023-36874/file_event_win_exploit_cve_2023_36874_wermgr_creation.kql) | high | execution | DeviceFileEvents |
| [Potential CVE-2023-36874 Exploitation - Fake Wermgr Execution](rules-emerging-threats/2023/Exploits/CVE-2023-36874/proc_creation_win_exploit_cve_2023_36874_fake_wermgr.kql) | high | execution | DeviceProcessEvents |
| [Potential CVE-2023-36884 Exploitation Dropped File](rules-emerging-threats/2023/Exploits/CVE-2023-36884/file_event_win_exploit_cve_2023_36884_office_windows_html_rce_file_patterns.kql) | medium | persistence, stealth | DeviceFileEvents |
| [CVE-2023-38331 Exploitation Attempt - Suspicious Double Extension File](rules-emerging-threats/2023/Exploits/CVE-2023-38831/file_event_win_exploit_cve_2023_38331_winrar_susp_double_ext.kql) | high | execution | DeviceFileEvents |
| [CVE-2023-38331 Exploitation Attempt - Suspicious WinRAR Child Process](rules-emerging-threats/2023/Exploits/CVE-2023-38831/proc_creation_win_exploit_cve_2023_38831_winrar_child_proc.kql) | high | execution, T1203 | DeviceProcessEvents |
| [Potential Exploitation Attempt Of Undocumented WindowsServer RCE](rules-emerging-threats/2023/Exploits/Windows-Server-Unknown-Exploit/proc_creation_win_exploit_other_win_server_undocumented_rce.kql) | high | initial-access, T1190 | DeviceProcessEvents |
| [Potential COLDSTEEL RAT File Indicators](rules-emerging-threats/2023/Malware/COLDSTEEL/file_event_win_malware_coldsteel_renamed_cmd.kql) | high | persistence, stealth | DeviceFileEvents |
| [Potential COLDSTEEL Persistence Service DLL Creation](rules-emerging-threats/2023/Malware/COLDSTEEL/file_event_win_malware_coldsteel_service_dll_creation.kql) | high | persistence, stealth | DeviceFileEvents |
| [Potential COLDSTEEL Persistence Service DLL Load](rules-emerging-threats/2023/Malware/COLDSTEEL/image_load_malware_coldsteel_persistence_service_dll.kql) | high | persistence, stealth | DeviceImageLoadEvents |
| [COLDSTEEL RAT Anonymous User Process Execution](rules-emerging-threats/2023/Malware/COLDSTEEL/proc_creation_win_malware_coldsteel_anonymous_process.kql) | high | persistence, stealth | DeviceProcessEvents |
| [COLDSTEEL RAT Cleanup Command Execution](rules-emerging-threats/2023/Malware/COLDSTEEL/proc_creation_win_malware_coldsteel_cleanup.kql) | critical | persistence, stealth | DeviceProcessEvents |
| [COLDSTEEL RAT Service Persistence Execution](rules-emerging-threats/2023/Malware/COLDSTEEL/proc_creation_win_malware_coldsteel_service_persistence.kql) | critical | persistence, stealth | DeviceProcessEvents |
| [Potential COLDSTEEL RAT Windows User Creation](rules-emerging-threats/2023/Malware/COLDSTEEL/registry_set_malware_coldsteel_created_users.kql) | high | persistence | DeviceRegistryEvents |
| [DarkGate - Autoit3.EXE File Creation By Uncommon Process](rules-emerging-threats/2023/Malware/DarkGate/file_event_win_malware_darkgate_autoit3_binary_creation.kql) | medium | command-and-control, execution, T1105, T1059 | DeviceFileEvents |
| [DarkGate - Autoit3.EXE Execution Parameters](rules-emerging-threats/2023/Malware/DarkGate/proc_creation_win_malware_darkgate_autoit3_from_susp_parent_and_location.kql) | high | execution, T1059 | DeviceProcessEvents |
| [DarkGate - User Created Via Net.EXE](rules-emerging-threats/2023/Malware/DarkGate/proc_creation_win_malware_darkgate_net_user_creation.kql) | high | persistence, T1136.001 | DeviceProcessEvents |
| [Griffon Malware Attack Pattern](rules-emerging-threats/2023/Malware/Griffon/proc_creation_win_malware_griffon_patterns.kql) | critical | execution | DeviceProcessEvents |
| [Injected Browser Process Spawning Rundll32 - GuLoader Activity](rules-emerging-threats/2023/Malware/GuLoader/proc_creation_win_malware_guloader_execution.kql) | high | privilege-escalation, stealth, T1055 | DeviceProcessEvents |
| [IcedID Malware Suspicious Single Digit DLL Execution Via Rundll32](rules-emerging-threats/2023/Malware/IcedID/proc_creation_win_malware_icedid_rundll32_dllregisterserver.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Potential Pikabot C2 Activity](rules-emerging-threats/2023/Malware/Pikabot/net_connection_win_malware_pikabot_rundll32_activity.kql) | high | command-and-control, T1573 | DeviceNetworkEvents |
| [Potential Pikabot Infection - Suspicious Command Combinations Via Cmd.EXE](rules-emerging-threats/2023/Malware/Pikabot/proc_creation_win_malware_pikabot_combined_commands_execution.kql) | medium | command-and-control, execution, stealth, T1059.003, T1105, T1218 | DeviceProcessEvents |
| [Potential Pikabot Discovery Activity](rules-emerging-threats/2023/Malware/Pikabot/proc_creation_win_malware_pikabot_discovery.kql) | high | discovery, T1016, T1049, T1087 | DeviceProcessEvents |
| [Potential Pikabot Hollowing Activity](rules-emerging-threats/2023/Malware/Pikabot/proc_creation_win_malware_pikabot_rundll32_hollowing.kql) | high | privilege-escalation, stealth, T1055.012 | DeviceProcessEvents |
| [Pikabot Fake DLL Extension Execution Via Rundll32.EXE](rules-emerging-threats/2023/Malware/Pikabot/proc_creation_win_malware_pikabot_rundll32_uncommon_extension.kql) | high | execution, stealth | DeviceProcessEvents |
| [Qakbot Regsvr32 Calc Pattern](rules-emerging-threats/2023/Malware/Qakbot/proc_creation_win_malware_qakbot_regsvr32_calc_pattern.kql) | high | execution, stealth | DeviceProcessEvents |
| [Potential Qakbot Rundll32 Execution](rules-emerging-threats/2023/Malware/Qakbot/proc_creation_win_malware_qakbot_rundll32_execution.kql) | high | execution, stealth | DeviceProcessEvents |
| [Qakbot Rundll32 Exports Execution](rules-emerging-threats/2023/Malware/Qakbot/proc_creation_win_malware_qakbot_rundll32_exports.kql) | critical | execution, stealth | DeviceProcessEvents |
| [Qakbot Rundll32 Fake DLL Extension Execution](rules-emerging-threats/2023/Malware/Qakbot/proc_creation_win_malware_qakbot_rundll32_fake_dll_execution.kql) | critical | execution, stealth | DeviceProcessEvents |
| [Qakbot Uninstaller Execution](rules-emerging-threats/2023/Malware/Qakbot/proc_creation_win_malware_qakbot_uninstaller_cleanup.kql) | high | execution | DeviceProcessEvents |
| [Rhadamanthys Stealer Module Launch Via Rundll32.EXE](rules-emerging-threats/2023/Malware/Rhadamanthys/proc_creation_win_malware_rhadamanthys_stealer_dll_launch.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Rorschach Ransomware Execution Activity](rules-emerging-threats/2023/Malware/Rorschach/proc_creation_win_malware_rorschach_ransomware_activity.kql) | critical | execution, T1059.003, T1059.001 | DeviceProcessEvents |
| [SNAKE Malware Kernel Driver File Indicator](rules-emerging-threats/2023/Malware/SNAKE/file_event_win_malware_snake_encrypted_payload_ioc.kql) | critical | execution | DeviceFileEvents |
| [SNAKE Malware WerFault Persistence File Creation](rules-emerging-threats/2023/Malware/SNAKE/file_event_win_malware_snake_werfault_creation.kql) | high | execution | DeviceFileEvents |
| [Potential SNAKE Malware Installation CLI Arguments Indicator](rules-emerging-threats/2023/Malware/SNAKE/proc_creation_win_malware_snake_installer_cli_args.kql) | high | execution | DeviceProcessEvents |
| [Potential SNAKE Malware Installation Binary Indicator](rules-emerging-threats/2023/Malware/SNAKE/proc_creation_win_malware_snake_installer_exec.kql) | high | execution | DeviceProcessEvents |
| [Potential SNAKE Malware Persistence Service Execution](rules-emerging-threats/2023/Malware/SNAKE/proc_creation_win_malware_snake_service_execution.kql) | high | execution | DeviceProcessEvents |
| [SNAKE Malware Covert Store Registry Key](rules-emerging-threats/2023/Malware/SNAKE/registry_event_malware_snake_covert_store_key.kql) | high | persistence | DeviceRegistryEvents |
| [Potential Encrypted Registry Blob Related To SNAKE Malware](rules-emerging-threats/2023/Malware/SNAKE/registry_set_malware_snake_encrypted_key.kql) | medium | persistence | DeviceRegistryEvents |
| [Ursnif Redirection Of Discovery Commands](rules-emerging-threats/2023/Malware/Ursnif/proc_creation_win_malware_ursnif_cmd_redirection.kql) | high | execution, T1059 | DeviceProcessEvents |
| [Malicious DLL Load By Compromised 3CXDesktopApp](rules-emerging-threats/2023/TA/3CX-Supply-Chain/image_load_malware_3cx_compromise_susp_dll.kql) | critical | stealth | DeviceImageLoadEvents |
| [Potential Compromised 3CXDesktopApp Beaconing Activity - Netcon](rules-emerging-threats/2023/TA/3CX-Supply-Chain/net_connection_win_malware_3cx_compromise_beaconing_activity.kql) | high | command-and-control | DeviceNetworkEvents |
| [Potential Compromised 3CXDesktopApp Execution](rules-emerging-threats/2023/TA/3CX-Supply-Chain/proc_creation_win_malware_3cx_compromise_execution.kql) | high | stealth, T1218, execution | DeviceProcessEvents |
| [Potential Suspicious Child Process Of 3CXDesktopApp](rules-emerging-threats/2023/TA/3CX-Supply-Chain/proc_creation_win_malware_3cx_compromise_susp_children.kql) | high | command-and-control, execution, stealth, T1218 | DeviceProcessEvents |
| [Potential Compromised 3CXDesktopApp Update Activity](rules-emerging-threats/2023/TA/3CX-Supply-Chain/proc_creation_win_malware_3cx_compromise_susp_update.kql) | high | stealth, T1218, execution | DeviceProcessEvents |
| [DLL Names Used By SVR For GraphicalProton Backdoor](rules-emerging-threats/2023/TA/Cozy-Bear/image_load_apt_cozy_bear_graphical_proton_dlls.kql) | medium | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Diamond Sleet APT File Creation Indicators](rules-emerging-threats/2023/TA/Diamond-Sleet/file_event_win_apt_diamond_sleet_indicators.kql) | high | execution | DeviceFileEvents |
| [Diamond Sleet APT DLL Sideloading Indicators](rules-emerging-threats/2023/TA/Diamond-Sleet/image_load_apt_diamond_sleet_side_load.kql) | high | persistence, privilege-escalation, execution, stealth, T1574.001 | DeviceImageLoadEvents |
| [Diamond Sleet APT Process Activity Indicators](rules-emerging-threats/2023/TA/Diamond-Sleet/proc_creation_win_apt_diamond_sleet_indicators.kql) | high | execution | DeviceProcessEvents |
| [Diamond Sleet APT Scheduled Task Creation - Registry](rules-emerging-threats/2023/TA/Diamond-Sleet/registry_event_apt_diamond_sleet_scheduled_task.kql) | high | defense-impairment, T1685 | DeviceRegistryEvents |
| [Potential APT FIN7 Related PowerShell Script Created](rules-emerging-threats/2023/TA/FIN7/file_event_win_apt_fin7_powershell_scripts_naming_convention.kql) | high | execution, G0046 | DeviceFileEvents |
| [Potential APT FIN7 Reconnaissance/POWERTRASH Related Activity](rules-emerging-threats/2023/TA/FIN7/proc_creation_win_apt_fin7_powertrash_lateral_movement.kql) | high | execution, G0046 | DeviceProcessEvents |
| [Lace Tempest File Indicators](rules-emerging-threats/2023/TA/Lace-Tempest/file_event_win_apt_lace_tempest_indicators.kql) | high | execution | DeviceFileEvents |
| [Lace Tempest Cobalt Strike Download](rules-emerging-threats/2023/TA/Lace-Tempest/proc_creation_win_apt_lace_tempest_cobalt_strike_download.kql) | high | execution | DeviceProcessEvents |
| [Lace Tempest Malware Loader Execution](rules-emerging-threats/2023/TA/Lace-Tempest/proc_creation_win_apt_lace_tempest_loader_execution.kql) | high | execution | DeviceProcessEvents |
| [Lazarus APT DLL Sideloading Activity](rules-emerging-threats/2023/TA/Lazarus/image_load_apt_lazarus_side_load_activity.kql) | high | privilege-escalation, persistence, execution, stealth, T1574.001, G0032 | DeviceImageLoadEvents |
| [Mint Sandstorm - AsperaFaspex Suspicious Process Execution](rules-emerging-threats/2023/TA/Mint-Sandstorm/proc_creation_win_apt_mint_sandstorm_aspera_faspex_susp_child_process.kql) | critical | execution | DeviceProcessEvents |
| [Mint Sandstorm - Log4J Wstomcat Process Execution](rules-emerging-threats/2023/TA/Mint-Sandstorm/proc_creation_win_apt_mint_sandstorm_log4j_wstomcat_execution.kql) | high | execution | DeviceProcessEvents |
| [Mint Sandstorm - ManageEngine Suspicious Process Execution](rules-emerging-threats/2023/TA/Mint-Sandstorm/proc_creation_win_apt_mint_sandstorm_manage_engine_susp_child_process.kql) | critical | execution | DeviceProcessEvents |
| [Potential APT Mustang Panda Activity Against Australian Gov](rules-emerging-threats/2023/TA/Mustang-Panda-Australia-Campaign/proc_creation_win_apt_mustang_panda_indicators.kql) | high | execution, G0129 | DeviceProcessEvents |
| [Onyx Sleet APT File Creation Indicators](rules-emerging-threats/2023/TA/Onyx-Sleet/file_event_win_apt_onyx_sleet_indicators.kql) | high | execution | DeviceFileEvents |
| [PaperCut MF/NG Exploitation Related Indicators](rules-emerging-threats/2023/TA/PaperCut-Print-Management-Exploitation/proc_creation_win_papercut_print_management_exploitation_indicators.kql) | high | execution | DeviceProcessEvents |
| [PaperCut MF/NG Potential Exploitation](rules-emerging-threats/2023/TA/PaperCut-Print-Management-Exploitation/proc_creation_win_papercut_print_management_exploitation_pc_app.kql) | high | execution | DeviceProcessEvents |
| [Peach Sandstorm APT Process Activity Indicators](rules-emerging-threats/2023/TA/Peach-Sandstorm/proc_creation_win_apt_peach_sandstorm_indicators.kql) | high | execution | DeviceProcessEvents |
| [UNC4841 - Email Exfiltration File Pattern](rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/file_event_lnx_apt_unc4841_exfil_mail_pattern.kql) | high | execution, persistence, stealth | DeviceFileEvents |
| [UNC4841 - Barracuda ESG Exploitation Indicators](rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/file_event_lnx_apt_unc4841_file_indicators.kql) | high | execution, persistence, stealth | DeviceFileEvents |
| [UNC4841 - SSL Certificate Exfiltration Via Openssl](rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/proc_creation_lnx_apt_unc4841_openssl_connection.kql) | high | stealth, T1140 | DeviceProcessEvents |
| [UNC4841 - Download Compressed Files From Temp.sh Using Wget](rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/proc_creation_lnx_apt_unc4841_wget_download_compressed_file_tmep_sh.kql) | high | stealth, T1140 | DeviceProcessEvents |
| [UNC4841 - Download Tar File From Untrusted Direct IP Via Wget](rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/proc_creation_lnx_apt_unc4841_wget_download_tar_files_direct_ip.kql) | high | stealth, T1140 | DeviceProcessEvents |
| [UNC4841 - Potential SEASPY Execution](rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/proc_creation_lnx_atp_unc4841_seaspy_execution.kql) | critical | execution | DeviceProcessEvents |
| [CVE-2024-1708 - ScreenConnect Path Traversal Exploitation](rules-emerging-threats/2024/Exploits/CVE-2024-1708/file_event_win_exploit_cve_2024_1708_screenconnect.kql) | medium | persistence | DeviceFileEvents |
| [ScreenConnect User Database Modification](rules-emerging-threats/2024/Exploits/CVE-2024-1709/file_event_win_exploit_cve_2024_1709_user_database_modification_screenconnect.kql) | medium | persistence | DeviceFileEvents |
| [Potential Exploitation of CVE-2024-3094 - Suspicious SSH Child Process](rules-emerging-threats/2024/Exploits/CVE-2024-3094/proc_creation_lnx_exploit_cve_2024_3094_sshd_child_process.kql) | high | execution | DeviceProcessEvents |
| [Potential CVE-2024-3400 Exploitation - Palo Alto GlobalProtect OS Command Injection - File Creation](rules-emerging-threats/2024/Exploits/CVE-2024-3400/file_event_paloalto_globalprotect_exploit_cve_2024_3400_command_inject_file_creation.kql) | medium | execution | DeviceFileEvents |
| [Potential Exploitation of CVE-2024-37085 - Suspicious Creation Of ESX Admins Group](rules-emerging-threats/2024/Exploits/CVE-2024-37085/proc_creation_win_exploit_cve_2024_37085_esxi_admins_group_creation.kql) | high | execution | DeviceProcessEvents |
| [Potential CSharp Streamer RAT Loading .NET Executable Image](rules-emerging-threats/2024/Malware/CSharp-Streamer/image_load_malware_csharp_streamer_dotnet_load.kql) | high | command-and-control, T1219.002 | DeviceImageLoadEvents |
| [DarkGate - Drop DarkGate Loader In C:\Temp Directory](rules-emerging-threats/2024/Malware/DarkGate/file_event_win_malware_darkgate_autoit3_save_temp.kql) | medium | execution, T1059 | DeviceFileEvents |
| [Potential KamiKakaBot Activity - Lure Document Execution](rules-emerging-threats/2024/Malware/KamiKakaBot/proc_creation_win_malware_kamikakabot_lnk_lure_execution.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [Potential KamiKakaBot Activity - Shutdown Schedule Task Creation](rules-emerging-threats/2024/Malware/KamiKakaBot/proc_creation_win_malware_kamikakabot_schtasks_persistence.kql) | medium | persistence | DeviceProcessEvents |
| [Potential KamiKakaBot Activity - Winlogon Shell Persistence](rules-emerging-threats/2024/Malware/KamiKakaBot/registry_set_malware_kamikakabot_winlogon_persistence.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Potential Raspberry Robin CPL Execution Activity](rules-emerging-threats/2024/Malware/Raspberry-Robin/proc_creation_win_malware_raspberry_robin_rundll32_shell32_cpl_exection.kql) | high | execution, stealth, T1218.011 | DeviceProcessEvents |
| [Potential Kapeka Decrypted Backdoor Indicator](rules-emerging-threats/2024/Malware/kapeka/file_event_win_malware_kapeka_backdoor_indicators.kql) | high | stealth | DeviceFileEvents |
| [Kapeka Backdoor Loaded Via Rundll32.EXE](rules-emerging-threats/2024/Malware/kapeka/image_load_malware_kapeka_backdoor_wll.kql) | high | execution, stealth, T1204.002, T1218.011 | DeviceImageLoadEvents |
| [Kapeka Backdoor Persistence Activity](rules-emerging-threats/2024/Malware/kapeka/proc_creation_win_malware_kapeka_backdoor_persistence.kql) | high | privilege-escalation, execution, persistence, T1053.005 | DeviceProcessEvents |
| [Kapeka Backdoor Execution Via RunDLL32.EXE](rules-emerging-threats/2024/Malware/kapeka/proc_creation_win_malware_kapeka_backdoor_rundll32_execution.kql) | high | stealth, T1218.011 | DeviceProcessEvents |
| [Kapeka Backdoor Autorun Persistence](rules-emerging-threats/2024/Malware/kapeka/registry_set_malware_kapeka_backdoor_autorun_persistence.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Kapeka Backdoor Configuration Persistence](rules-emerging-threats/2024/Malware/kapeka/registry_set_malware_kapeka_backdoor_configuration.kql) | medium | persistence, defense-impairment, T1553.003 | DeviceRegistryEvents |
| [Potential APT FIN7 Exploitation Activity](rules-emerging-threats/2024/TA/FIN7/proc_creation_win_apt_fin7_exploitation_indicators.kql) | medium | execution, T1059.001, T1059.003 | DeviceProcessEvents |
| [Forest Blizzard APT - File Creation Activity](rules-emerging-threats/2024/TA/Forest-Blizzard/file_event_win_apt_forest_blizzard_activity.kql) | high | defense-impairment, T1685.001 | DeviceFileEvents |
| [Forest Blizzard APT - JavaScript Constrained File Creation](rules-emerging-threats/2024/TA/Forest-Blizzard/file_event_win_apt_forest_blizzard_constrained_js.kql) | medium | defense-impairment, T1685.001 | DeviceFileEvents |
| [Forest Blizzard APT - Custom Protocol Handler Creation](rules-emerging-threats/2024/TA/Forest-Blizzard/registry_set_apt_forest_blizzard_custom_protocol_handler.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [Forest Blizzard APT - Custom Protocol Handler DLL Registry Set](rules-emerging-threats/2024/TA/Forest-Blizzard/registry_set_apt_forest_blizzard_custom_protocol_handler_dll.kql) | high | privilege-escalation, persistence, T1547.001 | DeviceRegistryEvents |
| [ScreenConnect - SlashAndGrab Exploitation Indicators](rules-emerging-threats/2024/TA/SlashAndGrab-Exploitation-In-Wild/file_event_win_apt_unknown_exploitation_indicators.kql) | high | stealth | DeviceFileEvents |
| [Potential CVE-2026-33829 Exploitation - Windows Snipping Tool Remote File Path URI](rules-emerging-threats/2026/Exploits/CVE-2026-33829/proc_creation_win_exploit_cve_2026_33829.kql) | high | credential-access, T1187 | DeviceProcessEvents |

## rules-threat-hunting (51)

| Rule | Level | ATT&CK | Table |
|---|---|---|---|
| [Python Path Configuration File Creation - Linux](rules-threat-hunting/linux/file/file_event/file_event_lnx_python_path_configuration_files.kql) | medium | execution, T1059.006 | DeviceFileEvents |
| [Terminate Linux Process Via Kill](rules-threat-hunting/linux/process_creation/proc_creation_lnx_susp_process_termination_via_kill.kql) | medium | defense-impairment, T1685 | DeviceProcessEvents |
| [Python Path Configuration File Creation - MacOS](rules-threat-hunting/macos/file/file_event/file_event_macos_python_path_configuration_files.kql) | medium | execution, T1059.006 | DeviceFileEvents |
| [Clipboard Data Collection Via Pbpaste](rules-threat-hunting/macos/process_creation/proc_creation_macos_pbpaste_execution.kql) | medium | collection, credential-access, T1115 | DeviceProcessEvents |
| [Python Path Configuration File Creation - Windows](rules-threat-hunting/windows/file/file_event/file_event_win_python_path_configuration_files.kql) | medium | execution, T1059.006 | DeviceFileEvents |
| [Suspicious Creation TXT File in User Desktop](rules-threat-hunting/windows/file/file_event/file_event_win_susp_desktop_txt.kql) | medium | impact, T1486 | DeviceFileEvents |
| [VsCode Code Tunnel Execution File Indicator](rules-threat-hunting/windows/file/file_event/file_event_win_vscode_tunnel_indicators.kql) | medium | command-and-control | DeviceFileEvents |
| [WebDAV Temporary Local File Creation](rules-threat-hunting/windows/file/file_event/file_event_win_webdav_tmpfile_creation.kql) | medium | initial-access, resource-development, T1584, T1566 | DeviceFileEvents |
| [Non-DLL Extension File Renamed With DLL Extension](rules-threat-hunting/windows/file/file_rename/file_rename_win_non_dll_to_dll_ext.kql) | medium | stealth, T1036.008 | DeviceFileEvents |
| [Dbghelp/Dbgcore DLL Loaded By Uncommon/Suspicious Process](rules-threat-hunting/windows/image_load/image_load_dll_dbghelp_dbgcore_susp_load.kql) | medium | credential-access, T1003.001 | DeviceImageLoadEvents |
| [Dfsvc.EXE Network Connection To Non-Local IPs](rules-threat-hunting/windows/network_connection/net_connection_win_dfsvc_non_local_ip.kql) | medium | execution, T1203 | DeviceNetworkEvents |
| [Dllhost.EXE Initiated Network Connection To Non-Local IP Address](rules-threat-hunting/windows/network_connection/net_connection_win_dllhost_non_local_ip.kql) | medium | stealth, T1218, execution, T1559.001 | DeviceNetworkEvents |
| [Potentially Suspicious Azure Front Door Connection](rules-threat-hunting/windows/network_connection/net_connection_win_susp_azurefd_connection.kql) | medium | command-and-control, T1102.002, T1090.004 | DeviceNetworkEvents |
| [Network Connection Initiated From Users\Public Folder](rules-threat-hunting/windows/network_connection/net_connection_win_susp_initaited_public_folder.kql) | medium | command-and-control, T1105 | DeviceNetworkEvents |
| [Headless Process Launched Via Conhost.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_conhost_headless_execution.kql) | medium | execution, T1059.001, T1059.003 | DeviceProcessEvents |
| [Dynamic .NET Compilation Via Csc.EXE - Hunting](rules-threat-hunting/windows/process_creation/proc_creation_win_csc_compilation.kql) | medium | stealth, T1027.004 | DeviceProcessEvents |
| [File Download Via Curl.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_curl_download.kql) | medium | command-and-control, T1105 | DeviceProcessEvents |
| [Potential Data Exfiltration Via Curl.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_curl_fileupload.kql) | medium | exfiltration, command-and-control, T1567, T1105 | DeviceProcessEvents |
| [Curl.EXE Execution With Custom UserAgent](rules-threat-hunting/windows/process_creation/proc_creation_win_curl_useragent.kql) | medium | command-and-control, T1071.001 | DeviceProcessEvents |
| [ClickOnce Deployment Execution - Dfsvc.EXE Child Process](rules-threat-hunting/windows/process_creation/proc_creation_win_dfsvc_child_processes.kql) | medium | execution, stealth | DeviceProcessEvents |
| [Diskshadow Child Process Spawned](rules-threat-hunting/windows/process_creation/proc_creation_win_diskshadow_child_process.kql) | medium | stealth, T1218, execution | DeviceProcessEvents |
| [Diskshadow Script Mode Execution](rules-threat-hunting/windows/process_creation/proc_creation_win_diskshadow_script_mode.kql) | medium | stealth, T1218, execution | DeviceProcessEvents |
| [Potential DLL Sideloading Activity Via ExtExport.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_extexport_execution.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Potential Password Reconnaissance Via Findstr.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_findstr_password_recon.kql) | medium | credential-access, T1552.001 | DeviceProcessEvents |
| [New Self Extracting Package Created Via IExpress.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_iexpress_execution.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Microsoft Workflow Compiler Execution](rules-threat-hunting/windows/process_creation/proc_creation_win_microsoft_workflow_compiler_execution.kql) | medium | execution, stealth, T1127, T1218 | DeviceProcessEvents |
| [SMB over QUIC Via Net.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_net_quic.kql) | medium | lateral-movement, T1570 | DeviceProcessEvents |
| [Suspicious New Instance Of An Office COM Object](rules-threat-hunting/windows/process_creation/proc_creation_win_office_svchost_parent.kql) | medium | execution, stealth | DeviceProcessEvents |
| [Invocation Of Crypto-Classes From The "Cryptography" PowerShell Namespace](rules-threat-hunting/windows/process_creation/proc_creation_win_powershell_crypto_namespace.kql) | medium | execution, stealth, T1059.001, T1027.010 | DeviceProcessEvents |
| [Potentially Suspicious PowerShell Child Processes](rules-threat-hunting/windows/process_creation/proc_creation_win_powershell_susp_child_processes.kql) | medium | execution, T1059.001 | DeviceProcessEvents |
| [Remote Access Tool - Action1 Arbitrary Code Execution and Remote Sessions](rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_action1_code_exec_and_remote_sessions.kql) | medium | command-and-control, T1219.002 | DeviceProcessEvents |
| [Remote Access Tool - Ammy Admin Agent Execution](rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_ammyy_admin_execution.kql) | medium | execution, persistence | DeviceProcessEvents |
| [Remote Access Tool - Cmd.EXE Execution via AnyViewer](rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_anyviewer_shell_exec.kql) | medium | execution, persistence | DeviceProcessEvents |
| [Remote Access Tool - ScreenConnect Remote Command Execution - Hunting](rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_child_proc.kql) | medium | execution | DeviceProcessEvents |
| [DLL Call by Ordinal Via Rundll32.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_by_ordinal.kql) | medium | stealth, T1218.011 | DeviceProcessEvents |
| [Rundll32.EXE Calling DllRegisterServer Export Function Explicitly](rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_dllregisterserver.kql) | medium | stealth, T1218 | DeviceProcessEvents |
| [Scheduled Task Creation From Potential Suspicious Parent Location](rules-threat-hunting/windows/process_creation/proc_creation_win_schtasks_creation_from_susp_parent.kql) | medium | execution, persistence, privilege-escalation, T1053.005 | DeviceProcessEvents |
| [Potential CommandLine Obfuscation Using Unicode Characters](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_cli_obfuscation_unicode.kql) | medium | stealth, T1027 | DeviceProcessEvents |
| [Potentially Suspicious Compression Tool Parameters](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_compression_params.kql) | medium | collection, T1560.001 | DeviceProcessEvents |
| [EventLog Query Requests By Builtin Utilities](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_event_log_query.kql) | medium | T1552, credential-access | DeviceProcessEvents |
| [Execution From Webserver Root Folder](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_execution_path_webserver.kql) | medium | persistence, T1505.003 | DeviceProcessEvents |
| [Tunneling Tool Execution](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_exfil_and_tunneling_tool_execution.kql) | medium | exfiltration, command-and-control, T1041, T1572, T1071.001 | DeviceProcessEvents |
| [File or Folder Permissions Modifications](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_file_permission_modifications.kql) | medium | defense-impairment, T1222.001 | DeviceProcessEvents |
| [Use Short Name Path in Command Line](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_ntfs_short_name_path_use_cli.kql) | medium | stealth, T1564.004 | DeviceProcessEvents |
| [Manual Execution of Script Inside of a Compressed File](rules-threat-hunting/windows/process_creation/proc_creation_win_susp_script_exec_from_compressed_parent.kql) | medium | execution, T1059 | DeviceProcessEvents |
| [WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript](rules-threat-hunting/windows/process_creation/proc_creation_win_wscript_cscript_script_exec.kql) | medium | execution, T1059.005, T1059.007 | DeviceProcessEvents |
| [Arbitrary Command Execution Using WSL](rules-threat-hunting/windows/process_creation/proc_creation_win_wsl_arbitrary_command_execution.kql) | medium | execution, stealth, T1218, T1202 | DeviceProcessEvents |
| [Cab File Extraction Via Wusa.EXE](rules-threat-hunting/windows/process_creation/proc_creation_win_wusa_cab_files_extraction.kql) | medium | execution | DeviceProcessEvents |
| [Microsoft Office Trusted Location Updated](rules-threat-hunting/windows/registry/registry_set/registry_set_office_trusted_location.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |
| [Registry Set With Crypto-Classes From The "Cryptography" PowerShell Namespace](rules-threat-hunting/windows/registry/registry_set/registry_set_powershell_crypto_namespace.kql) | medium | execution, persistence, privilege-escalation, stealth, T1059.001, T1027.010, T1547.001 | DeviceRegistryEvents |
| [Service Binary in User Controlled Folder](rules-threat-hunting/windows/registry/registry_set/registry_set_service_image_path_user_controlled_folder.kql) | medium | persistence, defense-impairment, T1112 | DeviceRegistryEvents |

