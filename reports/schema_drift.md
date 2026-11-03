# Schema drift

Live schema: downloaded from https://xdrinternals.com/FullSchema-latest.json (209 tables)

Compares the schema bundled with pySigma-backend-kusto against the live Defender schema. Validation uses the live schema for every table it lists.

## AADSignInEventsBeta

- **Not in the live schema** (queries using these fail validation): RiskDetails
- **Type changed:** TokenIssuerType (int → string)
- New columns the backend doesn't know about: EndpointCall, EntraIdDeviceId, RiskEventTypes, RiskLevelDuringSignIn

## AADSpnSignInEventsBeta

- New columns the backend doesn't know about: IsConfidentialClient

## AlertEvidence

- New columns the backend doesn't know about: MachineGroup, SentinelWorkspaceIds, SourceSystem, TenantId, TimeGenerated, Type

## AlertInfo

- New columns the backend doesn't know about: MachineGroup, SentinelWorkspaceIds, SourceSystem, TenantId, TimeGenerated, Type

## BehaviorEntities

- New columns the backend doesn't know about: CloudPlatform, CloudResource, CloudResourceId, CloudResourceType, CloudSubscriptionId, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type, _BilledSize, _IsBillable, _ResourceId, _SubscriptionId

## BehaviorInfo

- New columns the backend doesn't know about: Insights, MachineGroup, SourceSystem, TenantId, TimeGenerated, Title, Type, _BilledSize, _IsBillable, _ResourceId, _SubscriptionId

## CloudAppEvents

- **Not in the live schema** (queries using these fail validation): Isp
- **Type changed:** LastSeenForUser (string → dynamic), UncommonForUser (string → dynamic)
- New columns the backend doesn't know about: AppInstanceId, ISP, SourceSystem, TenantId, TimeGenerated, Type

## CloudAuditEvents

- **Not in the live schema** (queries using these fail validation): Isp, ResourceId
- New columns the backend doesn't know about: Account, AuditSource, AwsResourceName, AzureResourceId, GcpFullResourceName, ISP, SourceSystem, TenantId, TimeGenerated, Type

## DeviceEvents

- **Not in the live schema** (queries using these fail validation):  InitiatingProcessVersionInfoInternalFileName
- New columns the backend doesn't know about: InitiatingProcessUniqueId, InitiatingProcessVersionInfoInternalFileName, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceFileCertificateInfo

- New columns the backend doesn't know about: MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceFileEvents

- New columns the backend doesn't know about: InitiatingProcessUniqueId, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceImageLoadEvents

- New columns the backend doesn't know about: InitiatingProcessUniqueId, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceInfo

- New columns the backend doesn't know about: AzureVmId, AzureVmSubscriptionId, CloudPlatforms, DeviceRoles, DiscoverySources, DlpInfo, FirmwareVersions, HardwareUuid, IsTransient, MitigationStatus, OsBuildRevision, RestrictedDeviceSecurityOperations, SourceSystem, TenantId, TimeGenerated, Type

## DeviceLogonEvents

- New columns the backend doesn't know about: InitiatingProcessUniqueId, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceNetworkEvents

- New columns the backend doesn't know about: InitiatingProcessUniqueId, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceNetworkInfo

- New columns the backend doesn't know about: MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceProcessEvents

- New columns the backend doesn't know about: InitiatingProcessUniqueId, MachineGroup, ProcessUniqueId, SourceSystem, TenantId, TimeGenerated, Type

## DeviceRegistryEvents

- New columns the backend doesn't know about: InitiatingProcessUniqueId, MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceTvmInfoGathering

- New columns the backend doesn't know about: MachineGroup, SourceSystem, TenantId, Type

## DeviceTvmInfoGatheringKB

- **Type changed:** Categories (dynamic → string), FieldName (string → datetime), IgId (string → datetime)
- New columns the backend doesn't know about: SourceSystem, TenantId, Type

## DeviceTvmSecureConfigurationAssessment

- New columns the backend doesn't know about: MachineGroup, SourceSystem, TenantId, TimeGenerated, Type

## DeviceTvmSecureConfigurationAssessmentKB

- New columns the backend doesn't know about: SourceSystem, TenantId, Type

## DeviceTvmSoftwareEvidenceBeta

- **Type changed:** LastSeenTime (string → datetime)
- New columns the backend doesn't know about: MachineGroup, SourceSystem, TenantId, Type

## DeviceTvmSoftwareInventory

- New columns the backend doesn't know about: MachineGroup, ProductCategory, SoftwareTags, SourceSystem, TenantId, Type

## DeviceTvmSoftwareVulnerabilities

- New columns the backend doesn't know about: AadDeviceId, CveMitigationStatus, MachineGroup, ProductCategory, SourceSystem, TenantId, Type

## DeviceTvmSoftwareVulnerabilitiesKB

- **Type changed:** AffectedSoftware (dynamic → string), CvssScore (string → real)
- New columns the backend doesn't know about: CveSupportability, CvssVector, EpssScore, SourceSystem, TenantId, Type

## EmailAttachmentInfo

- New columns the backend doesn't know about: AdditionalFields, FileExtension, SourceSystem, TenantId, TimeGenerated, Type

## EmailEvents

- **Not in the live schema** (queries using these fail validation): LatestDeliveryAction`*, LatestDeliveryLocation`*
- New columns the backend doesn't know about: Cc, Context, DistributionList, EmailSize, ExchangeTransportRule, ForwardingInformation, IsFirstContact, LatestDeliveryAction, LatestDeliveryLocation, OriginalConfidenceLevel, OriginalDetectionMethods, OriginalThreatTypes, RecipientDomain, SourceSystem, TenantId, ThreatClassification, TimeGenerated, To, Type

## EmailPostDeliveryEvents

- New columns the backend doesn't know about: ApproverUpn, EmailDirection, SenderFromAddress, SourceLocation, SourceSystem, TenantId, TimeGenerated, Type

## EmailUrlInfo

- New columns the backend doesn't know about: SourceSystem, TenantId, TimeGenerated, Type, UrlChainId, UrlChainPosition

## ExposureGraphEdges

- New columns the backend doesn't know about: SourceSystem, TenantId, Type

## ExposureGraphNodes

- New columns the backend doesn't know about: SourceSystem, TenantId, Type

## IdentityDirectoryEvents

- New columns the backend doesn't know about: SourceSystem, TenantId, TimeGenerated, Type

## IdentityInfo

- **Not in the live schema** (queries using these fail validation): AccountDomain` [*](#mdi-only), AssignedRoles` [*](#mdi-only), ChangeSource` [*](#mdi-only), CreatedDateTime` [*](#mdi-only), DistinguishedName` [*](#mdi-only), Manager` [*](#mdi-only), Phone` [*](#mdi-only), ReportId` [*](#mdi-only), SourceProvider` [*](#mdi-only), SourceSystem` [*](#mdi-only), Tags` [*](#mdi-only), Timestamp` [*](#mdi-only), Type` [*](#mdi-only)
- New columns the backend doesn't know about: AccountDomain, AssignedRoles, BlastRadius, ChangeSource, CompanyName, CreatedDateTime, CriticalityLevel, DeletedDateTime, DistinguishedName, EmployeeId, GroupMembership, IdentityEnvironment, IdentityId, Manager, OnPremObjectId, OtherMailAddresses, Phone, PrivilegedEntraPimRoles, ReportId, RiskLevel, RiskLevelDetails, RiskScore, RiskScoreUpdateTime, RiskStatus, SourceProvider, SourceProviders, SourceSystem, State, Tags, TenantMembershipType, TimeGenerated, Timestamp, Type, UserAccountControl

## IdentityLogonEvents

- **Not in the live schema** (queries using these fail validation): Isp
- New columns the backend doesn't know about: ISP, LastSeenForUser, SourceSystem, TenantId, TimeGenerated, Type, UncommonForUser

## IdentityQueryEvents

- New columns the backend doesn't know about: SourceSystem, TenantId, TimeGenerated, Type

## UrlClickEvents

- New columns the backend doesn't know about: AppName, AppVersion, SourceId, SourceSystem, TenantId, TimeGenerated, Type

## Tables only in the bundled schema

Kept for validation because the live export doesn't list them: DeviceTvmHardwareFirmware

