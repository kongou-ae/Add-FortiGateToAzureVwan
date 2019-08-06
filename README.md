# Add-FortiGateToAzureVwan[WIP]

The PowerShell script to add FortiGate to Azure Virtual WAN

This script configure the following step automatically.

1. Azure: Create Resource Group if not present.
2. Azure: Create Azure Virtual wan if not present.
3. Azure: Add Virtual Hub if not present.
4. Azure: Add VPN Site to Virtual Wan.
5. Azure: Add a VPN Gateway scale unit to Virtual Hub.
6. Azure: Create Hub Association between Virtual Hub and VPN Site.
7. Azure: Download the configuration for S2S VPN.
8. FortiGate: Create loopback for BGP session.
9. FortiGate: Create ipsec tunnels.
10. FortiGate: Add firewall policies.
11. FortiGate: Add static routes for bgp neighbor.
12. FortiGate: Create route-maps to configure two tunnels as Active/Standby.
13. FortiGate: Configure BGP.