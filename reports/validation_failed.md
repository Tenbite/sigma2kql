# Queries that failed KQL validation

These converted, but Microsoft's Kusto parser rejected them against the target schema, so they were not written to the KQL folder.

## NotPetya Ransomware Activity

`rules-emerging-threats/2017/Malware/NotPetya/proc_creation_win_malware_notpetya.yml`

- The operator 'or' is not defined for the operand types bool and string. (at 354)

```kql
DeviceProcessEvents
| where (ProcessCommandLine contains "wevtutil cl Application & fsutil usn deletejournal /D C:" or ProcessCommandLine contains "dllhost.dat %WINDIR%\\ransoms") or (FolderPath endswith "\\rundll32.exe" and (ProcessCommandLine endswith ".dat,#1" or ProcessCommandLine endswith ".dat #1" or ProcessCommandLine endswith ".zip.dll\",#1")) or "\\perfc.dat"
```

## HH.EXE Initiated HTTP Network Connection

`rules-threat-hunting/windows/network_connection/net_connection_win_hh_http_connection.yml`

- A value of type string or dynamic expected. (at 81)

```kql
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\hh.exe" and (RemotePort in~ ("80", "443"))
```

## Elevated System Shell Spawned

`rules-threat-hunting/windows/process_creation/proc_creation_win_susp_elevated_system_shell.yml`

- The operator '=~' is not defined for the operand types long and string. (at 380)

```kql
DeviceProcessEvents
| where (((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "powershell_ise.EXE", "pwsh.dll", "Cmd.Exe"))) and ((AccountName contains "AUTHORI" or AccountName contains "AUTORI") and LogonId =~ "0x3e7")) and (not((InitiatingProcessFolderPath endswith "\\svchost.exe" or (InitiatingProcessFolderPath endswith "\\cmd.exe" and InitiatingProcessCommandLine =~ "C:\\Windows\\system32\\cmd.exe /d /c C:\\Windows\\system32\\silcollector.cmd configure"))))
```

## Potentially Suspicious Malware Callback Communication - Linux

`rules/linux/network_connection/net_connection_lnx_susp_malware_callback_port.yml`

- A value of type string or dynamic expected. (at 29)

```kql
DeviceNetworkEvents
| where (RemotePort in~ ("888", "999", "2200", "2222", "4000", "4444", "6789", "8531", "50501", "51820")) and (not((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7"))))
```

## Uncommon Network Connection Initiated By Certutil.EXE

`rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml`

- A value of type string or dynamic expected. (at 87)

```kql
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\certutil.exe" and (RemotePort in~ ("80", "135", "443", "445"))
```

## Office Application Initiated Network Connection To Non-Local IP

`rules/windows/network_connection/net_connection_win_office_outbound_non_local_ip.yml`

- A value of type string or dynamic expected. (at 3074)
- A value of type string or dynamic expected. (at 4461)
- A value of type string or dynamic expected. (at 5719)
- A value of type string or dynamic expected. (at 6936)
- A value of type string or dynamic expected. (at 7952)

```kql
DeviceNetworkEvents
| where (InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe") and (not(((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7")) or (ipv4_is_in_range(RemoteIP, "2.16.56.0/23") or ipv4_is_in_range(RemoteIP, "2.17.248.0/21") or ipv4_is_in_range(RemoteIP, "13.107.240.0/21") or ipv4_is_in_range(RemoteIP, "20.184.0.0/13") or ipv4_is_in_range(RemoteIP, "23.61.224.0/20") or ipv4_is_in_range(RemoteIP, "20.192.0.0/10") or ipv4_is_in_range(RemoteIP, "23.72.0.0/13") or ipv4_is_in_range(RemoteIP, "23.3.88.0/22") or ipv4_is_in_range(RemoteIP, "23.216.132.0/22") or ipv4_is_in_range(RemoteIP, "40.76.0.0/14") or ipv4_is_in_range(RemoteIP, "51.10.0.0/15") or ipv4_is_in_range(RemoteIP, "51.103.0.0/16") or ipv4_is_in_range(RemoteIP, "51.104.0.0/15") or ipv4_is_in_range(RemoteIP, "51.142.136.0/22") or ipv4_is_in_range(RemoteIP, "52.160.0.0/11") or ipv4_is_in_range(RemoteIP, "95.101.96.0/21") or ipv4_is_in_range(RemoteIP, "204.79.197.0/24")) or ((ipv4_is_in_range(RemoteIP, "13.107.4.0/22") or ipv4_is_in_range(RemoteIP, "13.107.6.152/31") or ipv4_is_in_range(RemoteIP, "13.107.18.10/31") or ipv4_is_in_range(RemoteIP, "13.107.42.0/23") or ipv4_is_in_range(RemoteIP, "13.107.128.0/22") or ipv4_is_in_range(RemoteIP, "23.35.224.0/20") or ipv4_is_in_range(RemoteIP, "23.53.40.0/22") or ipv4_is_in_range(RemoteIP, "23.103.160.0/20") or ipv4_is_in_range(RemoteIP, "23.216.76.0/22") or ipv4_is_in_range(RemoteIP, "40.96.0.0/13") or ipv4_is_in_range(RemoteIP, "40.104.0.0/15") or ipv4_is_in_range(RemoteIP, "52.96.0.0/14") or ipv4_is_in_range(RemoteIP, "131.253.33.215/32") or ipv4_is_in_range(RemoteIP, "132.245.0.0/16") or ipv4_is_in_range(RemoteIP, "150.171.32.0/22") or ipv4_is_in_range(RemoteIP, "204.79.197.215/32") or ipv4_is_in_range(RemoteIP, "2603:1006::/40") or ipv4_is_in_range(RemoteIP, "2603:1016::/36") or ipv4_is_in_range(RemoteIP, "2603:1026::/36") or ipv4_is_in_range(RemoteIP, "2603:1036::/36") or ipv4_is_in_range(RemoteIP, "2603:1046::/36") or ipv4_is_in_range(RemoteIP, "2603:1056::/36") or ipv4_is_in_range(RemoteIP, "2620:1ec:4::152/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:4::153/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:c::10/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:c::11/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:d::10/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:d::11/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:8f0::/46") or ipv4_is_in_range(RemoteIP, "2620:1ec:900::/46") or ipv4_is_in_range(RemoteIP, "2620:1ec:a92::152/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:a92::153/128")) and (RemotePort in~ ("80", "443"))) or ((ipv4_is_in_range(RemoteIP, "13.107.6.152/31") or ipv4_is_in_range(RemoteIP, "13.107.18.10/31") or ipv4_is_in_range(RemoteIP, "13.107.128.0/22") or ipv4_is_in_range(RemoteIP, "23.103.160.0/20") or ipv4_is_in_range(RemoteIP, "40.96.0.0/13") or ipv4_is_in_range(RemoteIP, "40.104.0.0/15") or ipv4_is_in_range(RemoteIP, "52.96.0.0/14") or ipv4_is_in_range(RemoteIP, "131.253.33.215/32") or ipv4_is_in_range(RemoteIP, "132.245.0.0/16") or ipv4_is_in_range(RemoteIP, "150.171.32.0/22") or ipv4_is_in_range(RemoteIP, "204.79.197.215/32") or ipv4_is_in_range(RemoteIP, "2603:1006::/40") or ipv4_is_in_range(RemoteIP, "2603:1016::/36") or ipv4_is_in_range(RemoteIP, "2603:1026::/36") or ipv4_is_in_range(RemoteIP, "2603:1036::/36") or ipv4_is_in_range(RemoteIP, "2603:1046::/36") or ipv4_is_in_range(RemoteIP, "2603:1056::/36") or ipv4_is_in_range(RemoteIP, "2620:1ec:4::152/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:4::153/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:c::10/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:c::11/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:d::10/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:d::11/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:8f0::/46") or ipv4_is_in_range(RemoteIP, "2620:1ec:900::/46") or ipv4_is_in_range(RemoteIP, "2620:1ec:a92::152/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:a92::153/128")) and (RemotePort in~ ("143", "587", "993", "995")) and Protocol =~ "tcp") or ((ipv4_is_in_range(RemoteIP, "40.92.0.0/15") or ipv4_is_in_range(RemoteIP, "40.107.0.0/16") or ipv4_is_in_range(RemoteIP, "52.100.0.0/14") or ipv4_is_in_range(RemoteIP, "52.238.78.88/32") or ipv4_is_in_range(RemoteIP, "104.47.0.0/17") or ipv4_is_in_range(RemoteIP, "2a01:111:f400::/48") or ipv4_is_in_range(RemoteIP, "2a01:111:f403::/48")) and RemotePort == 443) or ((ipv4_is_in_range(RemoteIP, "40.92.0.0/15") or ipv4_is_in_range(RemoteIP, "40.107.0.0/16") or ipv4_is_in_range(RemoteIP, "52.100.0.0/14") or ipv4_is_in_range(RemoteIP, "52.238.78.88/32") or ipv4_is_in_range(RemoteIP, "104.47.0.0/17") or ipv4_is_in_range(RemoteIP, "2a01:111:f400::/48") or ipv4_is_in_range(RemoteIP, "2a01:111:f403::/48")) and RemotePort == 25) or ((ipv4_is_in_range(RemoteIP, "13.107.136.0/22") or ipv4_is_in_range(RemoteIP, "40.108.128.0/17") or ipv4_is_in_range(RemoteIP, "52.104.0.0/14") or ipv4_is_in_range(RemoteIP, "104.146.128.0/17") or ipv4_is_in_range(RemoteIP, "150.171.40.0/22") or ipv4_is_in_range(RemoteIP, "2603:1061:1300::/40") or ipv4_is_in_range(RemoteIP, "2620:1ec:8f8::/46") or ipv4_is_in_range(RemoteIP, "2620:1ec:908::/46") or ipv4_is_in_range(RemoteIP, "2a01:111:f402::/48")) and (RemotePort in~ ("80", "443")) and Protocol =~ "tcp") or ((ipv4_is_in_range(RemoteIP, "13.107.6.171/32") or ipv4_is_in_range(RemoteIP, "13.107.18.15/32") or ipv4_is_in_range(RemoteIP, "13.107.140.6/32") or ipv4_is_in_range(RemoteIP, "20.64.0.0/10") or ipv4_is_in_range(RemoteIP, "52.108.0.0/14") or ipv4_is_in_range(RemoteIP, "52.244.37.168/32") or ipv4_is_in_range(RemoteIP, "2603:1006:1400::/40") or ipv4_is_in_range(RemoteIP, "2603:1016:2400::/40") or ipv4_is_in_range(RemoteIP, "2603:1026:2400::/40") or ipv4_is_in_range(RemoteIP, "2603:1036:2400::/40") or ipv4_is_in_range(RemoteIP, "2603:1046:1400::/40") or ipv4_is_in_range(RemoteIP, "2603:1056:1400::/40") or ipv4_is_in_range(RemoteIP, "2603:1063:2000::/38") or ipv4_is_in_range(RemoteIP, "2620:1ec:c::15/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:8fc::6/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:a92::171/128") or ipv4_is_in_range(RemoteIP, "2a01:111:f100:2000::a83e:3019/128") or ipv4_is_in_range(RemoteIP, "2a01:111:f100:2002::8975:2d79/128") or ipv4_is_in_range(RemoteIP, "2a01:111:f100:2002::8975:2da8/128") or ipv4_is_in_range(RemoteIP, "2a01:111:f100:7000::6fdd:6cd5/128") or ipv4_is_in_range(RemoteIP, "2a01:111:f100:a004::bfeb:88cf/128")) and (RemotePort in~ ("80", "443")) and Protocol =~ "tcp") or ((ipv4_is_in_range(RemoteIP, "172.128.0.0/10") or ipv4_is_in_range(RemoteIP, "20.20.32.0/19") or ipv4_is_in_range(RemoteIP, "20.103.156.88/32") or ipv4_is_in_range(RemoteIP, "20.190.128.0/18") or ipv4_is_in_range(RemoteIP, "20.231.128.0/19") or ipv4_is_in_range(RemoteIP, "40.126.0.0/18") or ipv4_is_in_range(RemoteIP, "57.150.0.0/15") or ipv4_is_in_range(RemoteIP, "2603:1006:2000::/48") or ipv4_is_in_range(RemoteIP, "2603:1007:200::/48") or ipv4_is_in_range(RemoteIP, "2603:1016:1400::/48") or ipv4_is_in_range(RemoteIP, "2603:1017::/48") or ipv4_is_in_range(RemoteIP, "2603:1026:3000::/48") or ipv4_is_in_range(RemoteIP, "2603:1027:1::/48") or ipv4_is_in_range(RemoteIP, "2603:1036:3000::/48") or ipv4_is_in_range(RemoteIP, "2603:1037:1::/48") or ipv4_is_in_range(RemoteIP, "2603:1046:2000::/48") or ipv4_is_in_range(RemoteIP, "2603:1047:1::/48") or ipv4_is_in_range(RemoteIP, "2603:1056:2000::/48") or ipv4_is_in_range(RemoteIP, "2603:1057:2::/48")) and (RemotePort in~ ("80", "443")) and Protocol =~ "tcp") or ((ipv4_is_in_range(RemoteIP, "13.64.0.0/11") or ipv4_is_in_range(RemoteIP, "13.107.6.192/32") or ipv4_is_in_range(RemoteIP, "13.107.9.192/32") or ipv4_is_in_range(RemoteIP, "13.89.179.14/32") or ipv4_is_in_range(RemoteIP, "20.40.0.0/14") or ipv4_is_in_range(RemoteIP, "20.48.0.0/12") or ipv4_is_in_range(RemoteIP, "20.64.0.0/12") or ipv4_is_in_range(RemoteIP, "52.123.0.0/16") or ipv4_is_in_range(RemoteIP, "52.108.0.0/14") or ipv4_is_in_range(RemoteIP, "52.136.0.0/13") or ipv4_is_in_range(RemoteIP, "57.150.0.0/15") or ipv4_is_in_range(RemoteIP, "80.239.150.67/32") or ipv4_is_in_range(RemoteIP, "2620:1ec:4::192/128") or ipv4_is_in_range(RemoteIP, "2620:1ec:a92::192/128")) and RemotePort == 443 and Protocol =~ "tcp") or (RemoteUrl endswith ".deploy.static.akamaitechnologies.com" and RemotePort == 443 and Protocol =~ "tcp"))))
```

## Office Application Initiated Network Connection Over Uncommon Ports

`rules/windows/network_connection/net_connection_win_office_uncommon_ports.yml`

- A value of type string or dynamic expected. (at 318)
- A value of type string or dynamic expected. (at 525)

```kql
DeviceNetworkEvents
| where (InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe") and (not(((RemotePort in~ ("53", "80", "139", "389", "443", "445", "3268")) or (InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft Office\\" and InitiatingProcessFolderPath endswith "\\OUTLOOK.EXE" and (RemotePort in~ ("143", "465", "587", "993", "995"))))))
```

## RDP to HTTP or HTTPS Target Ports

`rules/windows/network_connection/net_connection_win_rdp_to_http.yml`

- A value of type string or dynamic expected. (at 108)

```kql
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\svchost.exe" and LocalPort == 3389 and (RemotePort in~ ("80", "443"))
```

## Silenttrinity Stager Msbuild Activity

`rules/windows/network_connection/net_connection_win_silenttrinity_stager_msbuild_activity.yml`

- A value of type string or dynamic expected. (at 86)

```kql
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\msbuild.exe" and (RemotePort in~ ("80", "443"))
```

## Potentially Suspicious Malware Callback Communication

`rules/windows/network_connection/net_connection_win_susp_malware_callback_port.yml`

- A value of type string or dynamic expected. (at 29)

```kql
DeviceNetworkEvents
| where (RemotePort in~ ("100", "198", "200", "243", "473", "666", "700", "743", "777", "1443", "1515", "1777", "1817", "1904", "1960", "2443", "2448", "3360", "3675", "3939", "4040", "4433", "4438", "4443", "4444", "4455", "5445", "5552", "5649", "6625", "7210", "7777", "8143", "8843", "9631", "9943", "10101", "12102", "12103", "12322", "13145", "13394", "13504", "13505", "13506", "13507", "14102", "14103", "14154", "49180", "65520", "65535")) and (not((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7")))) and (not((InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\")))
```

## Communication To Uncommon Destination Ports

`rules/windows/network_connection/net_connection_win_susp_malware_callback_ports_uncommon.yml`

- A value of type string or dynamic expected. (at 29)

```kql
DeviceNetworkEvents
| where (RemotePort in~ ("8080", "8888")) and (not((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7")))) and (not((InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\")))
```

## Suspicious Outbound SMTP Connections

`rules/windows/network_connection/net_connection_win_susp_outbound_smtp_connections.yml`

- A value of type string or dynamic expected. (at 29)

```kql
DeviceNetworkEvents
| where (RemotePort in~ ("25", "587", "465", "2525")) and (not(((InitiatingProcessFolderPath endswith "\\thunderbird.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe") or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft\\Exchange Server\\" or (InitiatingProcessFolderPath startswith "C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_" and InitiatingProcessFolderPath endswith "\\HxTsr.exe"))))
```

## Suspicious Wordpad Outbound Connections

`rules/windows/network_connection/net_connection_win_wordpad_uncommon_ports.yml`

- A value of type string or dynamic expected. (at 91)

```kql
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\wordpad.exe" and (not((RemotePort in~ ("80", "139", "443", "445", "465", "587", "993", "995"))))
```

## WmiPrvSE Spawned A Process

`rules/windows/process_creation/proc_creation_win_wmiprvse_spawning_process.yml`

- A value of type string or dynamic expected. (at 93)

```kql
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\WmiPrvSe.exe" and (not(((LogonId in~ ("0x3e7", "null")) or (AccountName contains "AUTHORI" or AccountName contains "AUTORI") or FolderPath endswith "\\WmiPrvSE.exe" or FolderPath endswith "\\WerFault.exe" or isnull(LogonId))))
```

