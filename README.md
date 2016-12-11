Cisco Firepower

Publisher: World Wide Technology
App Version: 1.1.8
Product Vendor: Cisco Systems
Product Name: Cisco Firepower
Product Version Supported (regex): ".*"
This app interfaces with Cisco Firepower devices to add or remove IP's or
networks to a Firepower Network Group Object, which is configured with an ACL

Configuration Variables

The below configuration variables are required for this App to operate on Cisco
Firepower. These are specified when configuring an asset in Phantom.

VARIABLE    REQUIRED    TYPE    DESCRIPTION
username    required    string    User with access to the Firepower node
network_group_object    required    string    Network Group Object
domain_name    required    string    Firepower Domain
firepower_host    required    string    Device IP/Hostname
password    required    password    Password
Supported Actions

test connectivity - Validate the asset configuration for connectivity
list networks in object - Lists currently blocked networks
block ip - Blocks an IP network
unblock ip - Unblocks an IP network
action: 'test connectivity'

Validate the asset configuration for connectivity

Type: test

Read only: True

This action logs into the Cisco Firepower device using a REST call

Action Parameters

No parameters are required for this action

Action Output

No Output

action: 'list networks in object'

Lists currently blocked networks

Type: investigate

Read only: True

Action Parameters

No parameters are required for this action

Action Output

DATA PATH    TYPE    CONTAINS
action_result.data.*.network    string    
action_result.status    string    
action_result.message    string    
action: 'block ip'

Blocks an IP network

Type: contain

Read only: True

Action Parameters

PARAMETER    REQUIRED    DESCRIPTION    TYPE    CONTAINS
destination_network    required    IP/network to block (X.X.X.X/NM)    string    
Action Output

No Output

action: 'unblock ip'

Unblocks an IP network

Type: correct

Read only: True

Action Parameters

PARAMETER    REQUIRED    DESCRIPTION    TYPE    CONTAINS
destination_network    required    IP/network to unBlock (X.X.X.X/NM)    string    
Action Output

No Output
