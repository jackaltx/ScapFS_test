@{
    AllNodes =
    @(
       @{
            NodeName = '*'

            # R-101009 WN16-AU-000285
            stigrule_101009_Manage = $true
            stigrule_101009_Other_Object_Access_Events_AuditFlag = 'Success'
            stigrule_101009_Other_Object_Access_Events_Ensure = 'Present'

            # R-101011 WN16-AU-000286
            stigrule_101011_Manage = $true
            stigrule_101011_Other_Object_Access_Events_AuditFlag = 'Failure'
            stigrule_101011_Other_Object_Access_Events_Ensure = 'Present'

            # R-87939 WN16-00-000350
            stigrule_87939_Manage = $true
            stigrule_87939_Fax_Ensure = 'Absent'

            # R-87941 WN16-00-000360
            stigrule_87941_Manage = $true
            stigrule_87941_Web_Ftp_Service_Ensure = 'Absent'

            # R-87943 WN16-00-000370
            stigrule_87943_Manage = $true
            stigrule_87943_PNRP_Ensure = 'Absent'

            # R-87945 WN16-00-000380
            stigrule_87945_Manage = $true
            stigrule_87945_Simple_TCPIP_Ensure = 'Absent'

            # R-87947 WN16-00-000390
            stigrule_87947_Manage = $true
            stigrule_87947_Telnet_Client_Ensure = 'Absent'

            # R-87949 WN16-00-000400
            stigrule_87949_Manage = $true
            stigrule_87949_TFTP_Client_Ensure = 'Absent'

            # R-87951 WN16-00-000410
            stigrule_87951_Manage = $true
            stigrule_87951_FS_SMB1_Ensure = 'Absent'

            # R-87953 WN16-00-000420
            stigrule_87953_Manage = $true
            stigrule_87953_PowerShell_v2_Ensure = 'Absent'

            # R-87959 WN16-00-000450
            # Please choose an appropriate DoD time source from http://tycho.usno.navy.mil/ntp.html
            stigrule_87959_Manage = $false
            stigrule_87959_NtpServer_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\Parameters'
            stigrule_87959_NtpServer_Ensure = 'Present'
            stigrule_87959_NtpServer_ValueData = 'your|DoD|time|server|url|here'
            stigrule_87959_NtpServer_ValueType = 'String'
            stigrule_87959_Type_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\Parameters'
            stigrule_87959_Type_Ensure = 'Present'
            stigrule_87959_Type_ValueData = 'NTP'
            stigrule_87959_Type_ValueType = 'String'
            stigrule_87959_CrossSiteSyncFlags_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
            stigrule_87959_CrossSiteSyncFlags_Ensure = 'Present'
            stigrule_87959_CrossSiteSyncFlags_ValueData = '2'
            stigrule_87959_CrossSiteSyncFlags_ValueType = 'Dword'
            stigrule_87959_EventLogFlags_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
            stigrule_87959_EventLogFlags_Ensure = 'Present'
            stigrule_87959_EventLogFlags_ValueData = '0'
            stigrule_87959_EventLogFlags_ValueType = 'Dword'
            stigrule_87959_ResolvePeerBackoffMaxTimes_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
            stigrule_87959_ResolvePeerBackoffMaxTimes_Ensure = 'Present'
            stigrule_87959_ResolvePeerBackoffMaxTimes_ValueData = '7'
            stigrule_87959_ResolvePeerBackoffMaxTimes_ValueType = 'Dword'
            stigrule_87959_ResolvePeerBackoffMinutes_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
            stigrule_87959_ResolvePeerBackoffMinutes_Ensure = 'Present'
            stigrule_87959_ResolvePeerBackoffMinutes_ValueData = '15'
            stigrule_87959_ResolvePeerBackoffMinutes_ValueType = 'Dword'
            stigrule_87959_SpecialPollInterval_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
            stigrule_87959_SpecialPollInterval_Ensure = 'Present'
            stigrule_87959_SpecialPollInterval_ValueData = '3600'
            stigrule_87959_SpecialPollInterval_ValueType = 'Dword'

            # R-87961 WN16-AC-000010
            stigrule_87961_Manage = $true
            stigrule_87961_Account_lockout_duration_Account_lockout_duration = '15'

            # R-87963 WN16-AC-000020
            stigrule_87963_Manage = $true
            stigrule_87963_Account_lockout_threshold_Account_lockout_threshold = '3'

            # R-87965 WN16-AC-000030
            stigrule_87965_Manage = $true
            stigrule_87965_Reset_account_lockout_counter_after_Reset_account_lockout_counter_after = '15'

            # R-87967 WN16-AC-000040
            stigrule_87967_Manage = $true
            stigrule_87967_Enforce_password_history_Enforce_password_history = '24'

            # R-87969 WN16-AC-000050
            stigrule_87969_Manage = $true
            stigrule_87969_Maximum_Password_Age_Maximum_Password_Age = '60'

            # R-87971 WN16-AC-000060
            stigrule_87971_Manage = $true
            stigrule_87971_Minimum_Password_Age_Minimum_Password_Age = '1'

            # R-87973 WN16-AC-000070
            stigrule_87973_Manage = $true
            stigrule_87973_Minimum_Password_Length_Minimum_Password_Length = '14'

            # R-87975 WN16-AC-000080
            stigrule_87975_Manage = $true
            stigrule_87975_Password_must_meet_complexity_requirements_Password_must_meet_complexity_requirements = 'Enabled'

            # R-87977 WN16-AC-000090
            stigrule_87977_Manage = $true
            stigrule_87977_Store_passwords_using_reversible_encryption_Store_passwords_using_reversible_encryption = 'Disabled'

            # R-88065 WN16-AU-000070
            stigrule_88065_Manage = $true
            stigrule_88065_Credential_Validation_AuditFlag = 'Success'
            stigrule_88065_Credential_Validation_Ensure = 'Present'

            # R-88067 WN16-AU-000080
            stigrule_88067_Manage = $true
            stigrule_88067_Credential_Validation_AuditFlag = 'Failure'
            stigrule_88067_Credential_Validation_Ensure = 'Present'

            # R-88069 WN16-DC-000230
            stigrule_88069_Manage = $true
            stigrule_88069_Computer_Account_Management_AuditFlag = 'Success'
            stigrule_88069_Computer_Account_Management_Ensure = 'Present'

            # R-88071 WN16-AU-000100
            stigrule_88071_Manage = $true
            stigrule_88071_Other_Account_Management_Events_AuditFlag = 'Success'
            stigrule_88071_Other_Account_Management_Events_Ensure = 'Present'

            # R-88075 WN16-AU-000120
            stigrule_88075_Manage = $true
            stigrule_88075_Security_Group_Management_AuditFlag = 'Success'
            stigrule_88075_Security_Group_Management_Ensure = 'Present'

            # R-88079 WN16-AU-000140
            stigrule_88079_Manage = $true
            stigrule_88079_User_Account_Management_AuditFlag = 'Success'
            stigrule_88079_User_Account_Management_Ensure = 'Present'

            # R-88081 WN16-AU-000150
            stigrule_88081_Manage = $true
            stigrule_88081_User_Account_Management_AuditFlag = 'Failure'
            stigrule_88081_User_Account_Management_Ensure = 'Present'

            # R-88083 WN16-AU-000160
            stigrule_88083_Manage = $true
            stigrule_88083_PNP_Activity_AuditFlag = 'Success'
            stigrule_88083_PNP_Activity_Ensure = 'Present'

            # R-88085 WN16-AU-000170
            stigrule_88085_Manage = $true
            stigrule_88085_Process_Creation_AuditFlag = 'Success'
            stigrule_88085_Process_Creation_Ensure = 'Present'

            # R-88087 WN16-DC-000240
            stigrule_88087_Manage = $true
            stigrule_88087_Directory_Service_Access_AuditFlag = 'Success'
            stigrule_88087_Directory_Service_Access_Ensure = 'Present'

            # R-88089 WN16-DC-000250
            stigrule_88089_Manage = $true
            stigrule_88089_Directory_Service_Access_AuditFlag = 'Failure'
            stigrule_88089_Directory_Service_Access_Ensure = 'Present'

            # R-88091 WN16-DC-000260
            stigrule_88091_Manage = $true
            stigrule_88091_Directory_Service_Changes_AuditFlag = 'Success'
            stigrule_88091_Directory_Service_Changes_Ensure = 'Present'

            # R-88093 WN16-DC-000270
            stigrule_88093_Manage = $true
            stigrule_88093_Directory_Service_Changes_AuditFlag = 'Failure'
            stigrule_88093_Directory_Service_Changes_Ensure = 'Present'

            # R-88095 WN16-AU-000220
            stigrule_88095_Manage = $true
            stigrule_88095_Account_Lockout_AuditFlag = 'Success'
            stigrule_88095_Account_Lockout_Ensure = 'Present'

            # R-88097 WN16-AU-000230
            stigrule_88097_Manage = $true
            stigrule_88097_Account_Lockout_AuditFlag = 'Failure'
            stigrule_88097_Account_Lockout_Ensure = 'Present'

            # R-88099 WN16-AU-000240
            stigrule_88099_Manage = $true
            stigrule_88099_Group_Membership_AuditFlag = 'Success'
            stigrule_88099_Group_Membership_Ensure = 'Present'

            # R-88101 WN16-AU-000250
            stigrule_88101_Manage = $true
            stigrule_88101_Logoff_AuditFlag = 'Success'
            stigrule_88101_Logoff_Ensure = 'Present'

            # R-88103 WN16-AU-000260
            stigrule_88103_Manage = $true
            stigrule_88103_Logon_AuditFlag = 'Success'
            stigrule_88103_Logon_Ensure = 'Present'

            # R-88105 WN16-AU-000270
            stigrule_88105_Manage = $true
            stigrule_88105_Logon_AuditFlag = 'Failure'
            stigrule_88105_Logon_Ensure = 'Present'

            # R-88107 WN16-AU-000280
            stigrule_88107_Manage = $true
            stigrule_88107_Special_Logon_AuditFlag = 'Success'
            stigrule_88107_Special_Logon_Ensure = 'Present'

            # R-88109 WN16-AU-000290
            stigrule_88109_Manage = $true
            stigrule_88109_Removable_Storage_AuditFlag = 'Success'
            stigrule_88109_Removable_Storage_Ensure = 'Present'

            # R-88111 WN16-AU-000300
            stigrule_88111_Manage = $true
            stigrule_88111_Removable_Storage_AuditFlag = 'Failure'
            stigrule_88111_Removable_Storage_Ensure = 'Present'

            # R-88113 WN16-AU-000310
            stigrule_88113_Manage = $true
            stigrule_88113_Policy_Change_AuditFlag = 'Success'
            stigrule_88113_Policy_Change_Ensure = 'Present'

            # R-88115 WN16-AU-000320
            stigrule_88115_Manage = $true
            stigrule_88115_Policy_Change_AuditFlag = 'Failure'
            stigrule_88115_Policy_Change_Ensure = 'Present'

            # R-88117 WN16-AU-000330
            stigrule_88117_Manage = $true
            stigrule_88117_Authentication_Policy_Change_AuditFlag = 'Success'
            stigrule_88117_Authentication_Policy_Change_Ensure = 'Present'

            # R-88119 WN16-AU-000340
            stigrule_88119_Manage = $true
            stigrule_88119_Authorization_Policy_Change_AuditFlag = 'Success'
            stigrule_88119_Authorization_Policy_Change_Ensure = 'Present'

            # R-88121 WN16-AU-000350
            stigrule_88121_Manage = $true
            stigrule_88121_Sensitive_Privilege_Use_AuditFlag = 'Success'
            stigrule_88121_Sensitive_Privilege_Use_Ensure = 'Present'

            # R-88123 WN16-AU-000360
            stigrule_88123_Manage = $true
            stigrule_88123_Sensitive_Privilege_Use_AuditFlag = 'Failure'
            stigrule_88123_Sensitive_Privilege_Use_Ensure = 'Present'

            # R-88125 WN16-AU-000370
            stigrule_88125_Manage = $true
            stigrule_88125_IPsec_Driver_AuditFlag = 'Success'
            stigrule_88125_IPsec_Driver_Ensure = 'Present'

            # R-88127 WN16-AU-000380
            stigrule_88127_Manage = $true
            stigrule_88127_IPsec_Driver_AuditFlag = 'Failure'
            stigrule_88127_IPsec_Driver_Ensure = 'Present'

            # R-88129 WN16-AU-000390
            stigrule_88129_Manage = $true
            stigrule_88129_Other_System_Events_AuditFlag = 'Success'
            stigrule_88129_Other_System_Events_Ensure = 'Present'

            # R-88131 WN16-AU-000400
            stigrule_88131_Manage = $true
            stigrule_88131_Other_System_Events_AuditFlag = 'Failure'
            stigrule_88131_Other_System_Events_Ensure = 'Present'

            # R-88133 WN16-AU-000410
            stigrule_88133_Manage = $true
            stigrule_88133_Security_State_Change_AuditFlag = 'Success'
            stigrule_88133_Security_State_Change_Ensure = 'Present'

            # R-88135 WN16-AU-000420
            stigrule_88135_Manage = $true
            stigrule_88135_Security_System_Extension_AuditFlag = 'Success'
            stigrule_88135_Security_System_Extension_Ensure = 'Present'

            # R-88139 WN16-CC-000280
            stigrule_88139_Manage = $true
            stigrule_88139_EnumerateAdministrators_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\'
            stigrule_88139_EnumerateAdministrators_Ensure = 'Present'
            stigrule_88139_EnumerateAdministrators_ValueData = '0'
            stigrule_88139_EnumerateAdministrators_ValueType = 'Dword'

            # R-88141 WN16-AU-000440
            stigrule_88141_Manage = $true
            stigrule_88141_System_Integrity_AuditFlag = 'Success'
            stigrule_88141_System_Integrity_Ensure = 'Present'

            # R-88143 WN16-AU-000450
            stigrule_88143_Manage = $true
            stigrule_88143_System_Integrity_AuditFlag = 'Failure'
            stigrule_88143_System_Integrity_Ensure = 'Present'

            # R-88145 WN16-CC-000010
            stigrule_88145_Manage = $true
            stigrule_88145_NoLockScreenSlideshow_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\'
            stigrule_88145_NoLockScreenSlideshow_Ensure = 'Present'
            stigrule_88145_NoLockScreenSlideshow_ValueData = '1'
            stigrule_88145_NoLockScreenSlideshow_ValueType = 'Dword'

            # R-88147 WN16-MS-000020
            stigrule_88147_Manage = $false
            stigrule_88147_LocalAccountTokenFilterPolicy_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            stigrule_88147_LocalAccountTokenFilterPolicy_Ensure = 'Present'
            stigrule_88147_LocalAccountTokenFilterPolicy_ValueData = '0'
            stigrule_88147_LocalAccountTokenFilterPolicy_ValueType = 'Dword'

            # R-88149 WN16-CC-000030
            stigrule_88149_Manage = $true
            stigrule_88149_UseLogonCredential_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\'
            stigrule_88149_UseLogonCredential_Ensure = 'Present'
            stigrule_88149_UseLogonCredential_ValueData = '0'
            stigrule_88149_UseLogonCredential_ValueType = 'Dword'

            # R-88151 WN16-CC-000040
            stigrule_88151_Manage = $true
            stigrule_88151_DisableIPSourceRouting_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\'
            stigrule_88151_DisableIPSourceRouting_Ensure = 'Present'
            stigrule_88151_DisableIPSourceRouting_ValueData = '2'
            stigrule_88151_DisableIPSourceRouting_ValueType = 'Dword'

            # R-88153 WN16-CC-000050
            stigrule_88153_Manage = $true
            stigrule_88153_DisableIPSourceRouting_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\'
            stigrule_88153_DisableIPSourceRouting_Ensure = 'Present'
            stigrule_88153_DisableIPSourceRouting_ValueData = '2'
            stigrule_88153_DisableIPSourceRouting_ValueType = 'Dword'

            # R-88155 WN16-CC-000060
            stigrule_88155_Manage = $true
            stigrule_88155_EnableICMPRedirect_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\'
            stigrule_88155_EnableICMPRedirect_Ensure = 'Present'
            stigrule_88155_EnableICMPRedirect_ValueData = '0'
            stigrule_88155_EnableICMPRedirect_ValueType = 'Dword'

            # R-88157 WN16-CC-000070
            stigrule_88157_Manage = $true
            stigrule_88157_NoNameReleaseOnDemand_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\'
            stigrule_88157_NoNameReleaseOnDemand_Ensure = 'Present'
            stigrule_88157_NoNameReleaseOnDemand_ValueData = '1'
            stigrule_88157_NoNameReleaseOnDemand_ValueType = 'Dword'

            # R-88159 WN16-CC-000080
            stigrule_88159_Manage = $true
            stigrule_88159_AllowInsecureGuestAuth_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\'
            stigrule_88159_AllowInsecureGuestAuth_Ensure = 'Present'
            stigrule_88159_AllowInsecureGuestAuth_ValueData = '0'
            stigrule_88159_AllowInsecureGuestAuth_ValueType = 'Dword'

            # R-88161 WN16-CC-000090
            stigrule_88161_Manage = $true
            stigrule_88161_____NETLOGON_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\'
            stigrule_88161_____NETLOGON_Ensure = 'Present'
            stigrule_88161_____NETLOGON_ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            stigrule_88161_____NETLOGON_ValueType = 'String'
            stigrule_88161_____SYSVOL_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\'
            stigrule_88161_____SYSVOL_Ensure = 'Present'
            stigrule_88161_____SYSVOL_ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            stigrule_88161_____SYSVOL_ValueType = 'String'

            # R-88163 WN16-CC-000100
            stigrule_88163_Manage = $true
            stigrule_88163_ProcessCreationIncludeCmdLine_Enabled_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'
            stigrule_88163_ProcessCreationIncludeCmdLine_Enabled_Ensure = 'Present'
            stigrule_88163_ProcessCreationIncludeCmdLine_Enabled_ValueData = '1'
            stigrule_88163_ProcessCreationIncludeCmdLine_Enabled_ValueType = 'Dword'

            # R-88165 WN16-CC-000110
            # Please ensure the hardware requirements are met. See https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements
            stigrule_88165_Manage = $false
            stigrule_88165_EnableVirtualizationBasedSecurity_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\'
            stigrule_88165_EnableVirtualizationBasedSecurity_Ensure = 'Present'
            stigrule_88165_EnableVirtualizationBasedSecurity_ValueData = '1'
            stigrule_88165_EnableVirtualizationBasedSecurity_ValueType = 'Dword'
            stigrule_88165_RequirePlatformSecurityFeatures_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\'
            stigrule_88165_RequirePlatformSecurityFeatures_Ensure = 'Present'
            stigrule_88165_RequirePlatformSecurityFeatures_ValueData = '1'
            stigrule_88165_RequirePlatformSecurityFeatures_ValueType = 'Dword'

            # R-88167 WN16-MS-000120
            # Please ensure the hardware requirements are met. See https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements
            stigrule_88167_Manage = $false
            stigrule_88167_LsaCfgFlags_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\'
            stigrule_88167_LsaCfgFlags_Ensure = 'Present'
            stigrule_88167_LsaCfgFlags_ValueData = '1'
            stigrule_88167_LsaCfgFlags_ValueType = 'Dword'

            # R-88173 WN16-CC-000140
            stigrule_88173_Manage = $true
            stigrule_88173_DriverLoadPolicy_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\'
            stigrule_88173_DriverLoadPolicy_Ensure = 'Present'
            stigrule_88173_DriverLoadPolicy_ValueData = '1'
            stigrule_88173_DriverLoadPolicy_ValueType = 'Dword'

            # R-88177 WN16-CC-000150
            stigrule_88177_Manage = $true
            stigrule_88177_NoGPOListChanges_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\'
            stigrule_88177_NoGPOListChanges_Ensure = 'Present'
            stigrule_88177_NoGPOListChanges_ValueData = '0'
            stigrule_88177_NoGPOListChanges_ValueType = 'Dword'

            # R-88179 WN16-CC-000160
            stigrule_88179_Manage = $true
            stigrule_88179_DisableWebPnPDownload_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\'
            stigrule_88179_DisableWebPnPDownload_Ensure = 'Present'
            stigrule_88179_DisableWebPnPDownload_ValueData = '1'
            stigrule_88179_DisableWebPnPDownload_ValueType = 'Dword'

            # R-88181 WN16-CC-000170
            stigrule_88181_Manage = $true
            stigrule_88181_DisableHTTPPrinting_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\'
            stigrule_88181_DisableHTTPPrinting_Ensure = 'Present'
            stigrule_88181_DisableHTTPPrinting_ValueData = '1'
            stigrule_88181_DisableHTTPPrinting_ValueType = 'Dword'

            # R-88185 WN16-CC-000180
            stigrule_88185_Manage = $true
            stigrule_88185_DontDisplayNetworkSelectionUI_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\'
            stigrule_88185_DontDisplayNetworkSelectionUI_Ensure = 'Present'
            stigrule_88185_DontDisplayNetworkSelectionUI_ValueData = '1'
            stigrule_88185_DontDisplayNetworkSelectionUI_ValueType = 'Dword'

            # R-88187 WN16-MS-000030
            stigrule_88187_Manage = $true
            stigrule_88187_EnumerateLocalUsers_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\'
            stigrule_88187_EnumerateLocalUsers_Ensure = 'Present'
            stigrule_88187_EnumerateLocalUsers_ValueData = '0'
            stigrule_88187_EnumerateLocalUsers_ValueType = 'Dword'

            # R-88197 WN16-CC-000210
            stigrule_88197_Manage = $true
            stigrule_88197_DCSettingIndex_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\'
            stigrule_88197_DCSettingIndex_Ensure = 'Present'
            stigrule_88197_DCSettingIndex_ValueData = '1'
            stigrule_88197_DCSettingIndex_ValueType = 'Dword'

            # R-88201 WN16-CC-000220
            stigrule_88201_Manage = $true
            stigrule_88201_ACSettingIndex_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\'
            stigrule_88201_ACSettingIndex_Ensure = 'Present'
            stigrule_88201_ACSettingIndex_ValueData = '1'
            stigrule_88201_ACSettingIndex_ValueType = 'Dword'

            # R-88203 WN16-MS-000040
            stigrule_88203_Manage = $true
            stigrule_88203_RestrictRemoteClients_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\'
            stigrule_88203_RestrictRemoteClients_Ensure = 'Present'
            stigrule_88203_RestrictRemoteClients_ValueData = '1'
            stigrule_88203_RestrictRemoteClients_ValueType = 'Dword'

            # R-88207 WN16-CC-000240
            stigrule_88207_Manage = $true
            stigrule_88207_DisableInventory_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat\'
            stigrule_88207_DisableInventory_Ensure = 'Present'
            stigrule_88207_DisableInventory_ValueData = '1'
            stigrule_88207_DisableInventory_ValueType = 'Dword'

            # R-88209 WN16-CC-000250
            stigrule_88209_Manage = $true
            stigrule_88209_NoAutoplayfornonVolume_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
            stigrule_88209_NoAutoplayfornonVolume_Ensure = 'Present'
            stigrule_88209_NoAutoplayfornonVolume_ValueData = '1'
            stigrule_88209_NoAutoplayfornonVolume_ValueType = 'Dword'

            # R-88211 WN16-CC-000260
            stigrule_88211_Manage = $true
            stigrule_88211_NoAutorun_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
            stigrule_88211_NoAutorun_Ensure = 'Present'
            stigrule_88211_NoAutorun_ValueData = '1'
            stigrule_88211_NoAutorun_ValueType = 'Dword'

            # R-88213 WN16-CC-000270
            stigrule_88213_Manage = $true
            stigrule_88213_NoDriveTypeAutoRun_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
            stigrule_88213_NoDriveTypeAutoRun_Ensure = 'Present'
            stigrule_88213_NoDriveTypeAutoRun_ValueData = '255'
            stigrule_88213_NoDriveTypeAutoRun_ValueType = 'Dword'

            # R-88215 WN16-CC-000290
            stigrule_88215_Manage = $true
            stigrule_88215_AllowTelemetry_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\'
            stigrule_88215_AllowTelemetry_Ensure = 'Present'
            stigrule_88215_AllowTelemetry_ValueData = '1'
            stigrule_88215_AllowTelemetry_ValueType = 'Dword'

            # R-88217 WN16-CC-000300
            stigrule_88217_Manage = $true
            stigrule_88217_MaxSize_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\'
            stigrule_88217_MaxSize_Ensure = 'Present'
            stigrule_88217_MaxSize_ValueData = '32768'
            stigrule_88217_MaxSize_ValueType = 'Dword'

            # R-88219 WN16-CC-000310
            stigrule_88219_Manage = $true
            stigrule_88219_MaxSize_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\'
            stigrule_88219_MaxSize_Ensure = 'Present'
            stigrule_88219_MaxSize_ValueData = '196608'
            stigrule_88219_MaxSize_ValueType = 'Dword'

            # R-88221 WN16-CC-000320
            stigrule_88221_Manage = $true
            stigrule_88221_MaxSize_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\'
            stigrule_88221_MaxSize_Ensure = 'Present'
            stigrule_88221_MaxSize_ValueData = '32768'
            stigrule_88221_MaxSize_ValueType = 'Dword'

            # R-88223 WN16-CC-000330
            stigrule_88223_Manage = $true
            stigrule_88223_EnableSmartScreen_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\'
            stigrule_88223_EnableSmartScreen_Ensure = 'Present'
            stigrule_88223_EnableSmartScreen_ValueData = '1'
            stigrule_88223_EnableSmartScreen_ValueType = 'Dword'

            # R-88225 WN16-CC-000340
            stigrule_88225_Manage = $true
            stigrule_88225_NoDataExecutionPrevention_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
            stigrule_88225_NoDataExecutionPrevention_Ensure = 'Present'
            stigrule_88225_NoDataExecutionPrevention_ValueData = '0'
            stigrule_88225_NoDataExecutionPrevention_ValueType = 'Dword'

            # R-88227 WN16-CC-000350
            stigrule_88227_Manage = $true
            stigrule_88227_NoHeapTerminationOnCorruption_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
            stigrule_88227_NoHeapTerminationOnCorruption_Ensure = 'Present'
            stigrule_88227_NoHeapTerminationOnCorruption_ValueData = '0'
            stigrule_88227_NoHeapTerminationOnCorruption_ValueType = 'Dword'

            # R-88229 WN16-CC-000360
            stigrule_88229_Manage = $true
            stigrule_88229_PreXPSP2ShellProtocolBehavior_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
            stigrule_88229_PreXPSP2ShellProtocolBehavior_Ensure = 'Present'
            stigrule_88229_PreXPSP2ShellProtocolBehavior_ValueData = '0'
            stigrule_88229_PreXPSP2ShellProtocolBehavior_ValueType = 'Dword'

            # R-88231 WN16-CC-000370
            stigrule_88231_Manage = $true
            stigrule_88231_DisablePasswordSaving_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'
            stigrule_88231_DisablePasswordSaving_Ensure = 'Present'
            stigrule_88231_DisablePasswordSaving_ValueData = '1'
            stigrule_88231_DisablePasswordSaving_ValueType = 'Dword'

            # R-88233 WN16-CC-000380
            stigrule_88233_Manage = $true
            stigrule_88233_fDisableCdm_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'
            stigrule_88233_fDisableCdm_Ensure = 'Present'
            stigrule_88233_fDisableCdm_ValueData = '1'
            stigrule_88233_fDisableCdm_ValueType = 'Dword'

            # R-88235 WN16-CC-000390
            stigrule_88235_Manage = $true
            stigrule_88235_fPromptForPassword_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'
            stigrule_88235_fPromptForPassword_Ensure = 'Present'
            stigrule_88235_fPromptForPassword_ValueData = '1'
            stigrule_88235_fPromptForPassword_ValueType = 'Dword'

            # R-88237 WN16-CC-000400
            stigrule_88237_Manage = $true
            stigrule_88237_fEncryptRPCTraffic_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'
            stigrule_88237_fEncryptRPCTraffic_Ensure = 'Present'
            stigrule_88237_fEncryptRPCTraffic_ValueData = '1'
            stigrule_88237_fEncryptRPCTraffic_ValueType = 'Dword'

            # R-88239 WN16-CC-000410
            stigrule_88239_Manage = $true
            stigrule_88239_MinEncryptionLevel_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'
            stigrule_88239_MinEncryptionLevel_Ensure = 'Present'
            stigrule_88239_MinEncryptionLevel_ValueData = '3'
            stigrule_88239_MinEncryptionLevel_ValueType = 'Dword'

            # R-88241 WN16-CC-000420
            stigrule_88241_Manage = $true
            stigrule_88241_DisableEnclosureDownload_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\'
            stigrule_88241_DisableEnclosureDownload_Ensure = 'Present'
            stigrule_88241_DisableEnclosureDownload_ValueData = '1'
            stigrule_88241_DisableEnclosureDownload_ValueType = 'Dword'

            # R-88243 WN16-CC-000430
            stigrule_88243_Manage = $true
            stigrule_88243_AllowBasicAuthInClear_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\'
            stigrule_88243_AllowBasicAuthInClear_Ensure = 'Present'
            stigrule_88243_AllowBasicAuthInClear_ValueData = '0'
            stigrule_88243_AllowBasicAuthInClear_ValueType = 'Dword'

            # R-88245 WN16-CC-000440
            stigrule_88245_Manage = $true
            stigrule_88245_AllowIndexingEncryptedStoresOrItems_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'
            stigrule_88245_AllowIndexingEncryptedStoresOrItems_Ensure = 'Present'
            stigrule_88245_AllowIndexingEncryptedStoresOrItems_ValueData = '0'
            stigrule_88245_AllowIndexingEncryptedStoresOrItems_ValueType = 'Dword'

            # R-88247 WN16-CC-000450
            stigrule_88247_Manage = $true
            stigrule_88247_EnableUserControl_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\'
            stigrule_88247_EnableUserControl_Ensure = 'Present'
            stigrule_88247_EnableUserControl_ValueData = '0'
            stigrule_88247_EnableUserControl_ValueType = 'Dword'

            # R-88249 WN16-CC-000460
            stigrule_88249_Manage = $true
            stigrule_88249_AlwaysInstallElevated_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\'
            stigrule_88249_AlwaysInstallElevated_Ensure = 'Present'
            stigrule_88249_AlwaysInstallElevated_ValueData = '0'
            stigrule_88249_AlwaysInstallElevated_ValueType = 'Dword'

            # R-88251 WN16-CC-000470
            stigrule_88251_Manage = $true
            stigrule_88251_SafeForScripting_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\'
            stigrule_88251_SafeForScripting_Ensure = 'Present'
            stigrule_88251_SafeForScripting_ValueData = '0'
            stigrule_88251_SafeForScripting_ValueType = 'Dword'

            # R-88253 WN16-CC-000480
            stigrule_88253_Manage = $true
            stigrule_88253_DisableAutomaticRestartSignOn_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'
            stigrule_88253_DisableAutomaticRestartSignOn_Ensure = 'Present'
            stigrule_88253_DisableAutomaticRestartSignOn_ValueData = '1'
            stigrule_88253_DisableAutomaticRestartSignOn_ValueType = 'Dword'

            # R-88255 WN16-CC-000490
            stigrule_88255_Manage = $true
            stigrule_88255_EnableScriptBlockLogging_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\'
            stigrule_88255_EnableScriptBlockLogging_Ensure = 'Present'
            stigrule_88255_EnableScriptBlockLogging_ValueData = '1'
            stigrule_88255_EnableScriptBlockLogging_ValueType = 'Dword'

            # R-88257 WN16-CC-000500
            stigrule_88257_Manage = $true
            stigrule_88257_AllowBasic_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\'
            stigrule_88257_AllowBasic_Ensure = 'Present'
            stigrule_88257_AllowBasic_ValueData = '0'
            stigrule_88257_AllowBasic_ValueType = 'Dword'

            # R-88263 WN16-CC-000530
            stigrule_88263_Manage = $true
            stigrule_88263_AllowBasic_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\'
            stigrule_88263_AllowBasic_Ensure = 'Present'
            stigrule_88263_AllowBasic_ValueData = '0'
            stigrule_88263_AllowBasic_ValueType = 'Dword'

            # R-88259 WN16-CC-000510
            stigrule_88259_Manage = $true
            stigrule_88259_AllowUnencryptedTraffic_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\'
            stigrule_88259_AllowUnencryptedTraffic_Ensure = 'Present'
            stigrule_88259_AllowUnencryptedTraffic_ValueData = '0'
            stigrule_88259_AllowUnencryptedTraffic_ValueType = 'Dword'

            # R-88265 WN16-CC-000540
            stigrule_88265_Manage = $true
            stigrule_88265_AllowUnencryptedTraffic_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\'
            stigrule_88265_AllowUnencryptedTraffic_Ensure = 'Present'
            stigrule_88265_AllowUnencryptedTraffic_ValueData = '0'
            stigrule_88265_AllowUnencryptedTraffic_ValueType = 'Dword'

            # R-88261 WN16-CC-000520
            stigrule_88261_Manage = $true
            stigrule_88261_AllowDigest_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\'
            stigrule_88261_AllowDigest_Ensure = 'Present'
            stigrule_88261_AllowDigest_ValueData = '0'
            stigrule_88261_AllowDigest_ValueType = 'Dword'

            # R-88267 WN16-CC-000550
            stigrule_88267_Manage = $true
            stigrule_88267_DisableRunAs_Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\'
            stigrule_88267_DisableRunAs_Ensure = 'Present'
            stigrule_88267_DisableRunAs_ValueData = '1'
            stigrule_88267_DisableRunAs_ValueType = 'Dword'

            # R-88269 WN16-PK-000010
            stigrule_88269_Manage = $false
            stigrule_88269_8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Location = 'LocalMachine'
            stigrule_88269_8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Store = 'Root'
            stigrule_88269_8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Path = 'C:\Certificates\8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561.cer'
            stigrule_88269_D73CA91102A2204A36459ED32213B467D7CE97FB_Location = 'LocalMachine'
            stigrule_88269_D73CA91102A2204A36459ED32213B467D7CE97FB_Store = 'Root'
            stigrule_88269_D73CA91102A2204A36459ED32213B467D7CE97FB_Path = 'C:\Certificates\D73CA91102A2204A36459ED32213B467D7CE97FB.cer'
            stigrule_88269_B8269F25DBD937ECAFD4C35A9838571723F2D026_Location = 'LocalMachine'
            stigrule_88269_B8269F25DBD937ECAFD4C35A9838571723F2D026_Store = 'Root'
            stigrule_88269_B8269F25DBD937ECAFD4C35A9838571723F2D026_Path = 'C:\Certificates\B8269F25DBD937ECAFD4C35A9838571723F2D026.cer'
            stigrule_88269_4ECB5CC3095670454DA1CBD410FC921F46B8564B_Location = 'LocalMachine'
            stigrule_88269_4ECB5CC3095670454DA1CBD410FC921F46B8564B_Store = 'Root'
            stigrule_88269_4ECB5CC3095670454DA1CBD410FC921F46B8564B_Path = 'C:\Certificates\4ECB5CC3095670454DA1CBD410FC921F46B8564B.cer'

            # R-88271 WN16-PK-000020
            stigrule_88271_Manage = $false
            stigrule_88271_22BBE981F0694D246CC1472ED2B021DC8540A22F_Location = 'LocalMachine'
            stigrule_88271_22BBE981F0694D246CC1472ED2B021DC8540A22F_Store = 'disallowed'
            stigrule_88271_22BBE981F0694D246CC1472ED2B021DC8540A22F_Path = 'C:\Certificates\22BBE981F0694D246CC1472ED2B021DC8540A22F.cer'
            stigrule_88271_AC06108CA348CC03B53795C64BF84403C1DBD341_Location = 'LocalMachine'
            stigrule_88271_AC06108CA348CC03B53795C64BF84403C1DBD341_Store = 'disallowed'
            stigrule_88271_AC06108CA348CC03B53795C64BF84403C1DBD341_Path = 'C:\Certificates\AC06108CA348CC03B53795C64BF84403C1DBD341.cer'

            # R-88273 WN16-PK-000030
            stigrule_88273_Manage = $false
            stigrule_88273_929BF3196896994C0A201DF4A5B71F603FEFBF2E_Location = 'LocalMachine'
            stigrule_88273_929BF3196896994C0A201DF4A5B71F603FEFBF2E_Store = 'disallowed'
            stigrule_88273_929BF3196896994C0A201DF4A5B71F603FEFBF2E_Path = 'C:\Certificates\929BF3196896994C0A201DF4A5B71F603FEFBF2E.cer'

            # R-88285 WN16-SO-000020
            stigrule_88285_Manage = $true
            stigrule_88285_Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only_Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

            # R-88287 WN16-SO-000030
            stigrule_88287_Manage = $false
            stigrule_88287_Accounts_Rename_administrator_account_Accounts_Rename_administrator_account = 'RenamedAdministrator'

            # R-88289 WN16-SO-000040
            stigrule_88289_Manage = $false
            stigrule_88289_Accounts_Rename_guest_account_Accounts_Rename_guest_account = 'RenamedGuest'

            # R-88291 WN16-SO-000050
            stigrule_88291_Manage = $true
            stigrule_88291_Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings_Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'

            # R-88293 WN16-DC-000320
            stigrule_88293_Manage = $true
            stigrule_88293_Domain_controller_LDAP_server_signing_requirements_Domain_controller_LDAP_server_signing_requirements = 'Require signing'

            # R-88295 WN16-DC-000330
            stigrule_88295_Manage = $true
            stigrule_88295_Domain_controller_Refuse_machine_account_password_changes_Domain_controller_Refuse_machine_account_password_changes = 'Disabled'

            # R-88297 WN16-SO-000080
            stigrule_88297_Manage = $true
            stigrule_88297_Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always_Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'

            # R-88299 WN16-SO-000090
            stigrule_88299_Manage = $true
            stigrule_88299_Domain_member_Digitally_encrypt_secure_channel_data_when_possible_Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'

            # R-88301 WN16-SO-000100
            stigrule_88301_Manage = $true
            stigrule_88301_Domain_member_Digitally_sign_secure_channel_data_when_possible_Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'

            # R-88303 WN16-SO-000110
            stigrule_88303_Manage = $true
            stigrule_88303_Domain_member_Disable_machine_account_password_changes_Domain_member_Disable_machine_account_password_changes = 'Disabled'

            # R-88305 WN16-SO-000120
            stigrule_88305_Manage = $true
            stigrule_88305_Domain_member_Maximum_machine_account_password_age_Domain_member_Maximum_machine_account_password_age = '30'

            # R-88307 WN16-SO-000130
            stigrule_88307_Manage = $true
            stigrule_88307_Domain_member_Require_strong_Windows_2000_or_later_session_key_Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'

            # R-88309 WN16-SO-000140
            stigrule_88309_Manage = $true
            stigrule_88309_Interactive_logon_Machine_inactivity_limit_Interactive_logon_Machine_inactivity_limit = '900'

            # R-88311 WN16-SO-000150
            stigrule_88311_Manage = $true
            stigrule_88311_Interactive_logon_Message_text_for_users_attempting_to_log_on_Interactive_logon_Message_text_for_users_attempting_to_log_on = 
@'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
'@

            # R-88313 WN16-SO-000160
            stigrule_88313_Manage = $true
            stigrule_88313_Interactive_logon_Message_title_for_users_attempting_to_log_on_Interactive_logon_Message_title_for_users_attempting_to_log_on = 'DoD Notice and Consent Banner'

            # R-88315 WN16-MS-000050
            stigrule_88315_Manage = $true
            stigrule_88315_Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available_Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'

            # R-88317 WN16-SO-000190
            stigrule_88317_Manage = $true
            stigrule_88317_Microsoft_network_client_Digitally_sign_communications_always_Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

            # R-88319 WN16-SO-000200
            stigrule_88319_Manage = $true
            stigrule_88319_Microsoft_network_client_Digitally_sign_communications_if_server_agrees_Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'

            # R-88321 WN16-SO-000210
            stigrule_88321_Manage = $true
            stigrule_88321_Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers_Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

            # R-88325 WN16-SO-000230
            stigrule_88325_Manage = $true
            stigrule_88325_Microsoft_network_server_Digitally_sign_communications_always_Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

            # R-88327 WN16-SO-000240
            stigrule_88327_Manage = $true
            stigrule_88327_Microsoft_network_server_Digitally_sign_communications_if_client_agrees_Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

            # R-88329 WN16-SO-000250
            stigrule_88329_Manage = $true
            stigrule_88329_Network_access_Allow_anonymous_SID_Name_translation_Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'

            # R-88331 WN16-SO-000260
            stigrule_88331_Manage = $true
            stigrule_88331_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'

            # R-88333 WN16-SO-000270
            stigrule_88333_Manage = $true
            stigrule_88333_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'

            # R-88337 WN16-SO-000290
            stigrule_88337_Manage = $true
            stigrule_88337_Network_access_Let_Everyone_permissions_apply_to_anonymous_users_Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'

            # R-88339 WN16-SO-000300
            stigrule_88339_Manage = $true
            stigrule_88339_Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares_Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'

            # R-88343 WN16-SO-000320
            stigrule_88343_Manage = $true
            stigrule_88343_Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM_Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'

            # R-88345 WN16-SO-000330
            stigrule_88345_Manage = $true
            stigrule_88345_Network_security_Allow_LocalSystem_NULL_session_fallback_Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

            # R-88347 WN16-SO-000340
            stigrule_88347_Manage = $true
            stigrule_88347_Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities_Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'

            # R-88351 WN16-SO-000360
            stigrule_88351_Manage = $true
            stigrule_88351_Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change_Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'

            # R-88355 WN16-SO-000380
            stigrule_88355_Manage = $true
            stigrule_88355_Network_security_LAN_Manager_authentication_level_Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'

            # R-88357 WN16-SO-000390
            stigrule_88357_Manage = $true
            stigrule_88357_Network_security_LDAP_client_signing_requirements_Network_security_LDAP_client_signing_requirements = 'Negotiate signing'

            # R-88359 WN16-SO-000400
            stigrule_88359_Manage = $true
            stigrule_88359_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'

            # R-88361 WN16-SO-000410
            stigrule_88361_Manage = $true
            stigrule_88361_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'

            # R-88363 WN16-SO-000420
            stigrule_88363_Manage = $true
            stigrule_88363_System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer_System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'

            # R-88365 WN16-SO-000430
            stigrule_88365_Manage = $true
            stigrule_88365_System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing_System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'

            # R-88369 WN16-SO-000450
            stigrule_88369_Manage = $true
            stigrule_88369_System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links_System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

            # R-88371 WN16-SO-000460
            stigrule_88371_Manage = $true
            stigrule_88371_User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account_User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'

            # R-88373 WN16-SO-000470
            stigrule_88373_Manage = $true
            stigrule_88373_User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop_User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'

            # R-88375 WN16-SO-000480
            stigrule_88375_Manage = $true
            stigrule_88375_User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode_User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'

            # R-88377 WN16-SO-000490
            stigrule_88377_Manage = $true
            stigrule_88377_User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users_User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'

            # R-88379 WN16-SO-000500
            stigrule_88379_Manage = $true
            stigrule_88379_User_Account_Control_Detect_application_installations_and_prompt_for_elevation_User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'

            # R-88381 WN16-SO-000510
            stigrule_88381_Manage = $true
            stigrule_88381_User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations_User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'

            # R-88383 WN16-SO-000520
            stigrule_88383_Manage = $true
            stigrule_88383_User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode_User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'

            # R-88385 WN16-SO-000530
            stigrule_88385_Manage = $true
            stigrule_88385_User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations_User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

            # R-88393 WN16-UR-000010
            stigrule_88393_Manage = $true
            stigrule_88393_Access_Credential_Manager_as_a_trusted_caller_Identity = ''

            # R-88395 WN16-DC-000340
            stigrule_88395_Manage = $false
            stigrule_88395_Access_this_computer_from_the_network_Identity = 'Administrators','Authenticated Users','Enterprise Domain Controllers'

            # R-88397 WN16-MS-000340
            stigrule_88397_Manage = $false
            stigrule_88397_Access_this_computer_from_the_network_Identity = 'Administrators','Authenticated Users'

            # R-88399 WN16-UR-000030
            stigrule_88399_Manage = $true
            stigrule_88399_Act_as_part_of_the_operating_system_Identity = ''

            # R-88401 WN16-DC-000350
            stigrule_88401_Manage = $true
            stigrule_88401_Add_workstations_to_domain_Identity = 'Administrators'

            # R-88403 WN16-UR-000050
            stigrule_88403_Manage = $true
            stigrule_88403_Allow_log_on_locally_Identity = 'Administrators'

            # R-88405 WN16-DC-000360
            stigrule_88405_Manage = $true
            stigrule_88405_Allow_log_on_through_Remote_Desktop_Services_Identity = 'Administrators'

            # R-88407 WN16-UR-000070
            stigrule_88407_Manage = $true
            stigrule_88407_Back_up_files_and_directories_Identity = 'Administrators'

            # R-88409 WN16-UR-000080
            stigrule_88409_Manage = $true
            stigrule_88409_Create_a_pagefile_Identity = 'Administrators'

            # R-88411 WN16-UR-000090
            stigrule_88411_Manage = $true
            stigrule_88411_Create_a_token_object_Identity = ''

            # R-88413 WN16-UR-000100
            stigrule_88413_Manage = $true
            stigrule_88413_Create_global_objects_Identity = 'Administrators','Service','Local Service','Network Service'

            # R-88415 WN16-UR-000110
            stigrule_88415_Manage = $true
            stigrule_88415_Create_permanent_shared_objects_Identity = ''

            # R-88417 WN16-UR-000120
            stigrule_88417_Manage = $true
            stigrule_88417_Create_symbolic_links_Identity = 'Administrators'

            # R-88419 WN16-UR-000130
            stigrule_88419_Manage = $true
            stigrule_88419_Debug_programs_Identity = 'Administrators'

            # R-88421 WN16-DC-000370
            stigrule_88421_Manage = $false
            stigrule_88421_Deny_access_to_this_computer_from_the_network_Identity = 'Guests'

            # R-88423 WN16-MS-000370
            stigrule_88423_Manage = $false
            stigrule_88423_Deny_access_to_this_computer_from_the_network_Identity = 'Enterprise Admins','Domain Admins','Local account','Guests'

            # R-88425 WN16-DC-000380
            stigrule_88425_Manage = $false
            stigrule_88425_Deny_log_on_as_a_batch_job_Identity = 'Guests'

            # R-88427 WN16-MS-000380
            stigrule_88427_Manage = $false
            stigrule_88427_Deny_log_on_as_a_batch_job_Identity = 'Enterprise Admins','Domain Admins','Guests'

            # R-88429 WN16-DC-000390
            stigrule_88429_Manage = $false
            stigrule_88429_Deny_log_on_as_a_service_Identity = ''

            # R-88431 WN16-MS-000390
            stigrule_88431_Manage = $false
            stigrule_88431_Deny_log_on_as_a_service_Identity = 'Enterprise Admins','Domain Admins'

            # R-88433 WN16-DC-000400
            stigrule_88433_Manage = $false
            stigrule_88433_Deny_log_on_locally_Identity = 'Guests'

            # R-88435 WN16-MS-000400
            stigrule_88435_Manage = $false
            stigrule_88435_Deny_log_on_locally_Identity = 'Enterprise Admins','Domain Admins','Guests'

            # R-88437 WN16-DC-000410
            stigrule_88437_Manage = $false
            stigrule_88437_Deny_log_on_through_Remote_Desktop_Services_Identity = 'Guests'

            # R-88439 WN16-MS-000410
            stigrule_88439_Manage = $false
            stigrule_88439_Deny_log_on_through_Remote_Desktop_Services_Identity = 'Enterprise Admins','Domain Admins','Local account','Guests'

            # R-88441 WN16-DC-000420
            stigrule_88441_Manage = $false
            stigrule_88441_Enable_computer_and_user_accounts_to_be_trusted_for_delegation_Identity = 'Administrators'

            # R-88443 WN16-MS-000420
            stigrule_88443_Manage = $false
            stigrule_88443_Enable_computer_and_user_accounts_to_be_trusted_for_delegation_Identity = ''

            # R-88445 WN16-UR-000200
            stigrule_88445_Manage = $true
            stigrule_88445_Force_shutdown_from_a_remote_system_Identity = 'Administrators'

            # R-88447 WN16-UR-000210
            stigrule_88447_Manage = $true
            stigrule_88447_Generate_security_audits_Identity = 'Local Service','Network Service'

            # R-88449 WN16-UR-000220
            stigrule_88449_Manage = $true
            stigrule_88449_Impersonate_a_client_after_authentication_Identity = 'Administrators','Service','Local Service','Network Service'

            # R-88451 WN16-UR-000230
            stigrule_88451_Manage = $true
            stigrule_88451_Increase_scheduling_priority_Identity = 'Administrators'

            # R-88453 WN16-UR-000240
            stigrule_88453_Manage = $true
            stigrule_88453_Load_and_unload_device_drivers_Identity = 'Administrators'

            # R-88455 WN16-UR-000250
            stigrule_88455_Manage = $true
            stigrule_88455_Lock_pages_in_memory_Identity = ''

            # R-88457 WN16-UR-000260
            stigrule_88457_Manage = $true
            stigrule_88457_Manage_auditing_and_security_log_Identity = 'Administrators'

            # R-88459 WN16-UR-000270
            stigrule_88459_Manage = $true
            stigrule_88459_Modify_firmware_environment_values_Identity = 'Administrators'

            # R-88461 WN16-UR-000280
            stigrule_88461_Manage = $true
            stigrule_88461_Perform_volume_maintenance_tasks_Identity = 'Administrators'

            # R-88463 WN16-UR-000290
            stigrule_88463_Manage = $true
            stigrule_88463_Profile_single_process_Identity = 'Administrators'

            # R-88465 WN16-UR-000300
            stigrule_88465_Manage = $true
            stigrule_88465_Restore_files_and_directories_Identity = 'Administrators'

            # R-88467 WN16-UR-000310
            stigrule_88467_Manage = $true
            stigrule_88467_Take_ownership_of_files_or_other_objects_Identity = 'Administrators'

            # R-88473 WN16-SO-000180
            stigrule_88473_Manage = $true
            stigrule_88473_Interactive_logon_Smart_card_removal_behavior_Interactive_logon_Smart_card_removal_behavior = 'Lock Workstation'

            # R-88475 WN16-SO-000010
            stigrule_88475_Manage = $true
            stigrule_88475_Accounts_Guest_account_status_Accounts_Guest_account_status = 'Disabled'

            # R-92829 WN16-00-000411
            stigrule_92829_Manage = $true
            stigrule_92829_SMB1_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\'
            stigrule_92829_SMB1_Ensure = 'Present'
            stigrule_92829_SMB1_ValueData = '0'
            stigrule_92829_SMB1_ValueType = 'Dword'

            # R-92831 WN16-00-000412
            stigrule_92831_Manage = $true
            stigrule_92831_Start_Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10\'
            stigrule_92831_Start_Ensure = 'Present'
            stigrule_92831_Start_ValueData = '4'
            stigrule_92831_Start_ValueType = 'Dword'
        }
       @{
            NodeName = 'localhost'
        }
    );
}

