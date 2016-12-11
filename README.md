# phantom_cisco_csr_rtbh

Cisco Cloud Services Router

Publisher: World Wide Technology
App Version: 1.3
Product Vendor: Cisco
Product Name: Cisco CSR
Product Version Supported (regex): ".*"
This app interfaces with Cisco CSR devices, and supports containment actions
like 'block network', correct actions like 'unblock network', and investigative
actions like 'list blocked networks' on a Cisco CSR device. It uses the REST
interface to log on and perform its actions. The target host is required to
have the REST interface enabled.

Configuration Variables

The below configuration variables are required for this App to operate on Cisco
CSR. These are specified when configuring an asset in Phantom.

VARIABLE    REQUIRED    TYPE    DESCRIPTION
password    required    password    Password
user    required    string    User with access to the trigger node
route_to_null    required    string    Null Route IP (x.x.x.x)
trigger_host    required    string    Trigger Host
Supported Actions

unblock network - Unblocks an IP/network
block network - Blocks an IP/network
list blocked networks - Lists currently blocked networks
test connectivity - Validate the asset configuration for connectivity
action: 'unblock network'

Unblocks an IP/network

Type: correct

Read only: True

Action Parameters

PARAMETER    REQUIRED    DESCRIPTION    TYPE    CONTAINS
destination-network    required    IP/network to unBlock (X.X.X.X/NM)    string    
Action Output

No Output

action: 'block network'

Blocks an IP/network

Type: contain

Read only: True

Action Parameters

PARAMETER    REQUIRED    DESCRIPTION    TYPE    CONTAINS
destination-network    required    IP/network to block (X.X.X.X/NM)    string    
Action Output

No Output

action: 'list blocked networks'

Lists currently blocked networks

Type: investigate

Read only: True

Action Parameters

No parameters are required for this action

Action Output

DATA PATH    TYPE    CONTAINS
action_result.data.*.destination-network    string    
action_result.status    string    
action_result.message    string    
action: 'test connectivity'

Validate the asset configuration for connectivity

Type: test

Read only: True

This action logs into the Cisco Cloud Services Router (CSR) using a REST API
call

Action Parameters

No parameters are required for this action

Action Output

No Output
