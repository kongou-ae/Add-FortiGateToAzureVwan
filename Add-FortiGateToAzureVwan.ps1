param(
    [parameter(mandatory=$true)][string]$resourceGroupName,
    [parameter(mandatory=$true)][string]$location,
    [parameter(mandatory=$true)][string]$vwanName,
    [parameter(mandatory=$true)][string]$vhubName,
    [parameter(mandatory=$true)][string]$vhubPrefix,
    [parameter(mandatory=$true)][string]$fortiGateGIP,
    [parameter(mandatory=$true)][string]$apiToken,
    [parameter(mandatory=$true)][string]$fortiGateAsn,
    [parameter(mandatory=$true)][string]$fortiGateBgpPeerIP,
    [parameter(mandatory=$true)][string]$fortiGateInterfaceNameForVPN,
    [parameter(mandatory=$true)][string]$fortiGateInterfaceNameForinternal    
    
)

function Out-Log {
    param (
        $logString
    )
    $now = Get-Date -Format "yyyy-MM-dd hh:mm:ss"
    Write-output "$now $logString"
}

$ErrorActionPreference = "stop"

# Disable the validation of private certificate

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

# Create resource group
if ($Null -eq (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction Continue) ){
    Out-Log "$resourceGroupName is nothing. Create $resourceGroupName in $location"
    $resourceGroup = New-AzResourceGroup -Name $resourceGroupName -Location $location
    $resourceGroupName = $resourceGroup.ResourceGroupName
}

# Create virtual wan
if ($Null -eq (Get-AzVirtualWan -ResourceGroupName $resourceGroupName -Name $vwanName -ErrorAction Continue) ){
    Out-Log "$vwanName is nothing. Create $vwanName in $resourceGroupName"
    $vwan = New-AzVirtualWan -ResourceGroupName $resourceGroupName -Name $vwanName -Location $location
}

# Create Virtual hub
if ($Null -eq (Get-AzVirtualHub -ResourceGroupName $resourceGroupName -Name $vhubName -ErrorAction Continue)){
    Out-Log "$vhubName is nothing. Create $vhubName in $vwanName. This operation may take 30 mins."
    $vhub = New-AzVirtualHub -ResourceGroupName $resourceGroupName -Name $vhubName -VirtualWan $vwan `
        -AddressPrefix $vhubPrefix -Location $location
}

# Create Hub association
if ($Null -eq ( Get-AzVpnGateway -ResourceGroupName $resourceGroupName -Name $vhubName )){
    $vpnGw = New-AzVpnGateway -ResourceGroupName $resourceGroupName -Name $vhubName -VpnGatewayScaleUnit 1 -VirtualHub $v
}

# Get the information of FortiGate
$apiPath = "cmdb/system/status/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$fgSystemStatus = Invoke-RestMethod -Method GET -Uri $url 

# Create vpn site
if ($null -eq (Get-AzVpnSite -ResourceGroupName $resourceGroupName -Name $fortiGateGIP -ErrorAction Continue)){
    Out-Log "$fortiGateGIP is nothing. Create $fortiGateGIP in $vwanname"
    $azVpnSite = New-AzVpnSite -ResourceGroupName $resourceGroupName -Name $fortiGateGIP -Location $location `
    -VirtualWanResourceGroupName $resourceGroupName -VirtualWanName $vwanName -IpAddress $fortiGateGIP `
    -DeviceModel $fgSystemStatus.serial -DeviceVendor "Fortinet" -BgpAsn $fortiGateAsn -BgpPeeringAddress $fortiGateBgpPeerIP
}

# Create VpnGateway
if ($Null -eq (Get-AzVpnGateway | Where-Object { $_.vhub.Id -like "*$vhubName"})){
    Out-Log "VpnGw in $vhubName is nothing. Create VpnGw in $vhubName"
    $vhub = Get-AzVirtualHub -ResourceGroupName $resourceGroupName -Name $vhubName
    $vpnGw = New-AzVpnGateway -ResourceGroupName $resourceGroupName `
        -Name "$vwan-$vhug-$((Get-date Format "yyyyMMdd-hhmm"))" -VpnGatewayScaleUnit 1 -VirtualHub $vhub
}

# Create hub association
$vpnGw = Get-AzVpnGateway | Where-Object { $_.VirtualHub.Id -like "*$vhubName"}
$psk = [System.Web.Security.Membership]::GeneratePassword(12,3)
Out-Log "PSK is $psk"
$psk = ConvertTo-SecureString $psk -AsPlainText -Force
Out-Log "Create VPN connection between VpnGw and VPN Site"
$vpnCon = New-AzVpnConnection -ResourceGroupName $resourceGroupName -ParentResourceName $vpnGw.Name `
    -Name $fortiGateGIP -VpnSite $azVpnSite -EnableBgp -SharedKey $psk

# Download the configuration for s2s VPN
Out-Log "Downloading the configuration for s2s VPN"
$time = (Get-date -Format "yyyyMMddHHmmss")
$storageAccountName = "vwanconfig$time"
$storageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -Location $location -SkuName Standard_LRS
$null = New-AzStorageContainer -Name "vpnconfig" -Permission Off -Context $storageAccount.Context
$sasUrl = New-AzStorageBlobSASToken -Container "vpnconfig" -Permission rwdl -FullUri -Blob "vpnconfig.json" -Context $storageAccount.Context 
$configSasUrl = Get-AzVirtualWanVpnConfiguration -StorageSasUrl $sasUrl -VpnSiteId $azVpnSite.id `
    -ResourceGroupName $resourceGroupName -Name $vwanName
$vpnSiteConfig = [System.Text.Encoding]::UTF8.GetString((Invoke-WebRequest -Uri $configSasUrl.SasUrl).Content) | ConvertFrom-Json

$vpnInstance0IpAddress =  $vpnSiteConfig.vpnSiteConnections.gatewayConfiguration.IpAddresses.Instance0
$vpnInstance1IpAddress =  $vpnSiteConfig.vpnSiteConnections.gatewayConfiguration.IpAddresses.Instance1
$vpnInstanceRemoteAs = $vpnSiteConfig.vpnSiteConnections.gatewayConfiguration.BgpSetting.Asn
$vpnInstance0RemotePeerIp = $vpnSiteConfig.vpnSiteConnections.gatewayConfiguration.BgpSetting.BgpPeeringAddresses.Instance0
$vpnInstance1RemotePeerIp = $vpnSiteConfig.vpnSiteConnections.gatewayConfiguration.BgpSetting.BgpPeeringAddresses.Instance1
$vpnPsk = $vpnSiteConfig.vpnSiteConnections.connectionConfiguration.PSK

# loopback for BGP
Out-log "Configure loopback interface for BGP"
$apiPath = "cmdb/system/interface/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "name" =  "interface"
    "json" = @{
        "name" = "vwanloopback"
        "mode" = "static"
        "ip" = "$fortiGateBgpPeerIP 255.255.255.255"
        "inferface" = ""
        "vdom" = "root"
        "type" = "loopback"
    }
} | ConvertTo-json
Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# ipsec-phase1-1
Out-log "Configure ipsec tunnel #1"
$apiPath = "cmdb/vpn.ipsec/phase1-interface/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "name" = "vwan-phase1-1"
    "json" = @{
        "name" = "vwan-phase1-1"
        "type" = "static"
        "interface" = $fortiGateInterfaceNameForVPN
        "peertype" = "any"
        "proposal" = "aes256-sha1"
        "wizard-type" = "custom"
        "remote-gw" = $vpnInstance0IpAddress
        "psksecret" = $vpnPsk
        "peerid" = ""
        "peer" = ""
        "peergrp" = ""
        "ipv4-split-include" = ""
        "split-include-service" = ""
        "ipv4-exclude-range" = ""
        "ip-version" = 4
        "ike-version" = 2
        "local-gw" = "0.0.0.0"
        "nattraversal" = "disable"
        "keylife" = 28880
        "authmethod"  = "psk"
        "authmethod-remote"  = ""
        "dpd" = "on-idle"
        "dhgrp" = 2
    }
} | ConvertTo-json

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# ipsec-phase2-1
$apiPath = "cmdb/vpn.ipsec/phase2-interface/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "json" = @{
        'name' = "vwan-phase2-1"
        'phase1name' = "vwan-phase1-1"
        'proposal' = "aes256-sha1"
        'pfs' = "disable"
        'dhgrp' = "14 5"
        'replay' = "enable"
        'keepalive' = "disable"
        'keylife-type' = "seconds"
        'keylifeseconds' = 27000
    }
} | ConvertTo-json

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# ipsec-phase1-2
Out-log "Configure ipsec tunnel #2"
$apiPath = "cmdb/vpn.ipsec/phase1-interface/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "name" = "vwan-phase1-2"
    "json" = @{
        "name" = "vwan-phase1-2"
        "type" = "static"
        "interface" = $fortiGateInterfaceNameForVPN
        "peertype" = "any"
        "proposal" = "aes256-sha1"
        "wizard-type" = "custom"
        "remote-gw" = $vpnInstance1IpAddress
        "psksecret" = $vpnPsk
        "peerid" = ""
        "peer" = ""
        "peergrp" = ""
        "ipv4-split-include" = ""
        "split-include-service" = ""
        "ipv4-exclude-range" = ""
        "ip-version" = 4
        "ike-version" = 2
        "local-gw" = "0.0.0.0"
        "nattraversal" = "disable"
        "keylife" = 28880
        "authmethod"  = "psk"
        "authmethod-remote"  = ""
        "dpd" = "on-idle"
        "dhgrp" = 2

    }
} | ConvertTo-json

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# ipsec-phase2-1
$apiPath = "cmdb/vpn.ipsec/phase2-interface/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "json" = @{
        'name' = "vwan-phase2-2"
        'phase1name' = "vwan-phase1-2"
        'proposal' = "aes256-sha1"
        'pfs' = "disable"
        'dhgrp' = "14 5"
        'replay' = "enable"
        'keepalive' = "disable"
        'keylife-type' = "seconds"
        'keylifeseconds' = 27000
    }
} | ConvertTo-json

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null


# firewall policy for vpn1
Out-log "Configure firewall policy for #1"
$apiPath = "cmdb/firewall/policy/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "name" = "vwan-phase1-1"
    "json" = @{
        "name" = "vwan-phase1-1"
        "srcintf" = @(
            @{
                "name" = $fortiGateInterfaceNameForinternal   
            }
        )
        "dstintf" = @(
            @{
                "name" = "vwan-phase1-1"
            }
        )
        "srcaddr" = @(
            @{
                "name" = "all"
            }
        )
        "dstaddr" = @(
            @{
                "name" = "all"
            }            
        )
        "action" = "accept"
        "schedule" = "always"
        "nat" = "disable"
        "status" = "enable"
        "ippool" = "disable"
        "traffic-shaper" = ""
        "traffic-shaper-reverse" = ""
        "poolname" = @{}
        "service" = @(
            @{
                "name" = "ALL_ICMP"
            }
        )
        "logtraffic" = "all"
    }
} | ConvertTo-json -Depth 100

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# firewall policy for vpn2
Out-log "Configure firewall policy for #2"
$apiPath = "cmdb/firewall/policy/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "name" = "vwan-phase1-2"
    "json" = @{
        "name" = "vwan-phase1-2"
        "srcintf" = @(
            @{
                "name" = $fortiGateInterfaceNameForinternal   
            }
        )
        "dstintf" = @(
            @{
                "name" = "vwan-phase1-2"
            }
        )
        "srcaddr" = @(
            @{
                "name" = "all"
            }
        )
        "dstaddr" = @(
            @{
                "name" = "all"
            }            
        )
        "action" = "accept"
        "schedule" = "always"
        "nat" = "disable"
        "status" = "enable"
        "ippool" = "disable"
        "traffic-shaper" = ""
        "traffic-shaper-reverse" = ""
        "poolname" = @{}
        "service" = @(
            @{
                "name" = "ALL_ICMP"
            }
        )
        "logtraffic" = "all"
    }
} | ConvertTo-json -Depth 100

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# Routing for accessing bgp neighbor
Out-log "Configure static routes to access bgp peer address of VpnGw"
$apiPath = "cmdb/router/static"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$body = @{
    "json" = @{
        "dst" = "$vpnInstance0RemotePeerIp 255.255.255.255"
        "device" = "vwan-phase1-1"

    }
} | ConvertTo-json -Depth 100

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

$body = @{
    "json" = @{
        "dst" = "$vpnInstance1RemotePeerIp 255.255.255.255"
        "device" = "vwan-phase1-2"

    }
} | ConvertTo-json -Depth 100

Invoke-RestMethod -Method Post -Uri $url -Body $body | Out-Null

# Lan prefix which fortigate advertizes
Out-log "Configure route maps to configure ipsec tunnels to Active/Standby"
$apiPath = "monitor/router/ipv4/"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"
$routes = Invoke-RestMethod -Method GET -Uri $url | foreach-object {$_.results} | Where-Object { $_.interface -eq $fortiGateInterfaceNameForinternal}

$convertTable = @{
    "1" =	"128.0.0.0"
    "2" =	"192.0.0.0"
    "3" =	"224.0.0.0"
    "4" =	"240.0.0.0"
    "5" =	"248.0.0.0"
    "6" =	"252.0.0.0"
    "7" =	"254.0.0.0"
    "8" =	"255.0.0.0"
    "9" =	"255.128.0.0"
    "10" = "255.192.0.0"
    "11" = "255.224.0.0"
    "12" = "255.240.0.0"
    "13" = "255.248.0.0"
    "14" = "255.252.0.0"
    "15" = "255.254.0.0"
    "16" = "255.255.0.0"
    "17" = "255.255.128.0"
    "18" = "255.255.192.0"
    "19" = "255.255.224.0"
    "20" = "255.255.240.0"
    "21" = "255.255.248.0"
    "22" = "255.255.252.0"
    "23" = "255.255.254.0"
    "24" = "255.255.255.0"
    "25" = "255.255.255.128"
    "26" = "255.255.255.192"
    "27" = "255.255.255.224"
    "28" = "255.255.255.240"
    "29" = "255.255.255.248"
    "30" = "255.255.255.252"
    "31" = "255.255.255.254"
    "32" = "255.255.255.255"
}

$prefix = ($routes.ip_mask -split "/")[0]
$subnetmask = ($routes.ip_mask -split "/")[1]
$subnetmask = $convertTable[$subnetmask]
$bgpNetwork = "$prefix $subnetmask"

# prefix-list for filter

$apiPath = "cmdb/router/prefix-list"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"

$body = @{
    "json" = @{
        "name" = "localnet"
        "rule" = @(
            @{
                "id" =  10
                "action" = "premit"
                "prefix" = $bgpNetwork
            }
        )
    }
} | convertto-json -Depth 100

Invoke-RestMethod -Method POST -Uri $url -Body $body | Out-Null

# Routmap for backup
$apiPath = "cmdb/router/route-map"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"

$body = @{
    "json" = @{
        "name" = "out-for-backup"
        "rule" = @(
            @{
                "id" =  20
                "match-flags" = 2
                "match-ip-address" = "localnet"
                "set-aspath" = @(
                    @{
                        "as" = "$fortiGateAsn $fortiGateAsn $fortiGateAsn"
                    }
                )
            }
        )
    }
} | convertto-json -Depth 100

Invoke-RestMethod -Method POST -Uri $url -Body $body | Out-Null

# Routmap for primary

$apiPath = "cmdb/router/route-map"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"

$body = @{
    "json" = @{
        "name" = "out-for-primary"
        "rule" = @(
            @{
                "id" =  20
                "match-flags" = 2
                "match-ip-address" = "localnet"
            }
        )
    }
} | convertto-json -Depth 100

Invoke-RestMethod -Method POST -Uri $url -Body $body | Out-Null

$body = @{
    "json" = @{
        "name" = "in-for-primary"
        "rule" = @(
            @{
                "id" =  1
                "set-local-preference" = 300
                "set-flags" = 512
            }
        )
    }
} | convertto-json -Depth 100

Invoke-RestMethod -Method POST -Uri $url -Body $body | Out-Null

# BGP configuration
Out-log "Configure BGP"
$apiPath = "cmdb/router/bgp"
$url = "https://$fortiGateGIP/api/v2/$($apiPath)?vdom=root&access_token=$apiToken"

$body = @{
    "json" = @{
        "as" = [int]$fortiGateAsn
        "router-id" = $fortiGateBgpPeerIP
        "log-neighbor-changes" = "enable"
        "graceful-restart" = "enable"
        "neighbor" = @(
            @{
                "ip" = $vpnInstance0RemotePeerIp
                "remote-as" = [int]$vpnInstanceRemoteAs
                "capability-graceful-restart" = "enable"
                "ebgp-enforce-multihop" = "enable"
                "soft-reconfiguration" = "enable"
                "update-source" = "vwanloopback"
                "route-map-in" = "in-for-primary"
                "route-map-out" = "out-for-primary"
            }
            @{
                "ip" = $vpnInstance1RemotePeerIp
                "remote-as" = [int]$vpnInstanceRemoteAs
                "capability-graceful-restart" = "enable"
                "ebgp-enforce-multihop" = "enable"
                "soft-reconfiguration" = "enable"
                "update-source" = "vwanloopback"
                "route-map-out" = "out-for-backup"
            }
        )
        "network" = @(
            @{
                "prefix" = $bgpNetwork
            }
        )
        "redistribute" = @(
            @{
                "name" = "connected"
                "status" = "disable"    
            },
            @{
                "name" = "rip"
                "status" = "disable"    
            },
            @{
                "name" = "ospf"
                "status" = "disable"    
            },
            @{
                "name" = "static"
                "status" = "disable"    
            },
            @{
                "name" = "isis"
                "status" = "disable"    
            }
        )
    }
} | ConvertTo-json -Depth 100

Invoke-RestMethod -Method PUT -Uri $url -Body $body | Out-Null

Out-log "Done. You should add virtual network connection manually."