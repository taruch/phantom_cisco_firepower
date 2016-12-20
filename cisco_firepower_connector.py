#
"""
     module: cisco_firepower_connector.py
     short_description: This Phantom app connects to the
        Cisco Firepower platform
     author: Todd Ruch, World Wide Technology
     Revision history:
     21 November 2016  |  1.1 - initial release
     See github page for updates and revision history.

     Copyright (c) 2016 World Wide Technology, Inc.

     This program is free software: you can redistribute it and/ori
     modify it under the terms of the GNU Affero General Public License
     as published by the Free Software Foundation, either version 3
     of the License, or (at your option) any later version.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU Affero General Public License for more details.


"""
#
# Phantom App imports
#
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
#
#  system imports
#
import simplejson as json
import time
import requests
from netaddr import IPNetwork

REST_PORT = '443'
TOKEN_RESOURCE = '/api/fmc_platform/v1/auth/generatetoken'
ACCEPT_HEADERS = {'Accept': 'application/json'}


# ========================================================
# AppConnector
# ========================================================


class FP_Connector(BaseConnector):

    BANNER = "Cisco_FirePower"

    def __init__(self):
        """
        Instance variables
        """
        # Call the BaseConnectors init first
        super(FP_Connector, self).__init__()

        # standard port for IOS XE REST API
        self.port = REST_PORT
        # base URI with version number
        self.BASE_URI = '/api/fmc_platform/v1'
        # resourse URI

        self.username = ''
        self.password = ''
        self.firepower_host = ''
        self.firepower_devices = []
        self.firepower_deployable_devices = []
        self.version = 'v1'
        self.network_group_object = ''
        self.domain_name = ''
        self.destination_network = ''
        self.destination_dict = {}
        self.js = ''
        self.TOKEN_RESOURCE = TOKEN_RESOURCE
        self.token = ''
        self.api_path = ''
        self.network_group_list = []
        self.domain_uuid = ''
        self.netgroup_uuid = ''
        self.network_group_name = ''
        self.headers = ACCEPT_HEADERS
        self.HEADER = {"Content-Type": "application/json"}
        self.status_code = []

    def initialize(self):
        """
        This is an optional function that can be implemented by the
        AppConnector derived class. Since the configuration dictionary
        is already validated by the time this function is called,
        it's a good place to do any extra initialization of any internal
        modules. This function MUST return a value of either
        phantom.APP_SUCCESS or phantom.APP_ERROR.  If this function
        returns phantom.APP_ERROR, then AppConnector::handle_action
        will not get called.
        """
        self.debug_print("%s INITIALIZE %s" % (FP_Connector.BANNER,
                                               time.asctime()))
        self.debug_print("INITAL CONFIG: %s" % self.get_config())
        return phantom.APP_SUCCESS

    def finalize(self):
        """
        This function gets called once all the param dictionary
        elements are looped over and no more handle_action calls are
        left to be made. It gives the AppConnector a chance to loop
        through all the results that were accumulated by multiple
        handle_action function calls and create any summary if
        required. Another usage is cleanup, disconnect from remote
        devices etc.
        """
        self.debug_print("%s FINALIZE Status: %s" % (FP_Connector.BANNER,
                                                     self.get_status()))
        return

    def handle_exception(self, exception_object):
        """
        All the code within BaseConnector::_handle_action is within
        a 'try: except:' clause.  Thus if an exception occurs during
        the execution of this code it is caught at a single place. The
        resulting exception object is passed to the
        AppConnector::handle_exception() to do any cleanup of it's own
        if required. This exception is then added to the connector run
        result and passed back to spawn, which gets displayed in the
        Phantom UI.
        """
        self.debug_print("%s HANDLE_EXCEPTION %s" % (FP_Connector.BANNER,
                                                     exception_object))
        return

    def _get_Config(self, param):
        """
        Initializes the main configuration variables from the required
        variables in the app.
        """
        config = self.get_config()

        try:
            self.firepower_host = config["firepower_host"]
            self.username = config["username"]
            self.password = config["password"]
            self.domain_name = config["domain_name"]
            self.network_group_object = config["network_group_object"]
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
            self.debug_print("Firepower Host: {0}".format(self.firepower_host))
            self.debug_print("Username: {0}".format(self.username))
            self.debug_print("Password: {0}".format(self.password))
            self.debug_print("Domain Name: {0}".format(self.domain_name))
            self.debug_print("Network Group Name:"
                             "{0}".format(self.network_group_object))
        # Everything requires a token, so just get it during
        # initialization
        self._get_token()
        # As everything is based on the group object UUID in the URI
        # just get this during intialization
        self._get_Group_Object_UUID()
        return

    def _get_Group_Object_UUID(self):
        """
        This method is responsible for getting the UUID associated with
        the network group object specified in the app config and setting
        the netgroup_uuid variable.
        """
        self.debug_print("Running _get_Group_Object_UUID")
        self.api_path = ("/api/fmc_config/v1/domain/"
                         "{0}/object/networkgroups".format(self.domain_uuid))
        self.debug_print("api_path: {0}".format(self.api_path))
        api_response = self.api_run('get', self.api_path)
        resp = api_response.text
        json_resp = json.loads(resp)
        self.debug_print("Network Group Object result RAW:"
                         "{0}".format(json.dumps(json_resp, indent=4)))
        try:
            network_group_list = json_resp['items']
            for item in network_group_list:
                if item['name'] == self.network_group_object:
                    self.netgroup_uuid = item['id']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
        self.debug_print("Network Group UUID: {0}".format(
                                                self.netgroup_uuid))
        return

    def _get_Group_Object_Networks(self):
        """
        """
        # Get the current list of static routes from the Target Host
        self.api_path = ("/api/fmc_config/v1/domain/"
                         "{0}/object/networkgroups/"
                         "{1}".format(self.domain_uuid, self.netgroup_uuid))
        self.debug_print("api_path: {0}".format(self.api_path))
        api_response = self.api_run('get', self.api_path)
        resp = api_response.text
        json_resp = json.loads(resp)
        self.debug_print("Network Group Object result RAW:"
                         "{0}".format(json.dumps(json_resp, indent=4)))
        try:
            self.network_group_list = json_resp['literals']
            self.debug_print("Network Group Object result: {0}".format(
                                                self.network_group_list))
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

    def _get_Firepower_Deployable_Devices(self):
        """
        """
        # Get the current list of devices in the domain
        self.api_path = ("/api/fmc_config/v1/domain/"
                         "{0}/deployment/deployabledevices"
                         "?limit=100&expanded=true".format(self.domain_uuid))
        self.debug_print("api_path: {0}".format(self.api_path))
        api_response = self.api_run('get', self.api_path)
        resp = api_response.text
        json_resp = json.loads(resp)
        # self.debug_print("Network Group Object result RAW:"
        #                 "{0}".format(json.dumps(json_resp, indent=4)))
        try:
            for item in json_resp['items']:
                self.firepower_deployable_devices.append(
                            {'name': item['device']['name'],
                             'id': item['device']['id']})
            self.debug_print("Firepower Deployable Devices:"
                             "{0}".format(self.firepower_deployable_devices))
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

    def _get_token(self):
        """
        """
        if not self.token:
            result = self.api_run('post', TOKEN_RESOURCE)
            self.debug_print("{0}".format(result))
            auth_headers = result.headers
            self.token = auth_headers.get('X-auth-access-token', default=None)
            self.debug_print("token id: {0}".format(self.token))
            self.domain_uuid = auth_headers.get('DOMAIN_UUID',
                                                default=None)
            self.debug_print("domain_uuid: {0}".format(self.domain_uuid))
            self.headers.update({'X-auth-access-token': self.token})
            return

    def build_url(self, rest_port=REST_PORT, resource=TOKEN_RESOURCE):
        """
        build a URL for the REST resource
        """
        self.url = 'https://{0}:{1}{2}'.format(self.firepower_host,
                                               self.port, resource)
        self.debug_print('set full URL to: {0}'.format(self.url))
        return

    def api_run(self, method, resource):
        """
        get/put/post/delete a request to the REST service
        """
        # a GET/POST/PUT/DELETE method name was passed in;
        # call the appropriate method from requests module
        request_method = getattr(requests, method)
        self.build_url(resource=resource)
        if self.js:
            self.headers.update({'Content-type': 'application/json'})
            result = request_method(self.url,
                                    auth=requests.auth.HTTPBasicAuth(
                                                self.username, self.password),
                                    headers=self.headers,
                                    data=json.dumps(self.js),
                                    verify=False)
        else:
            result = request_method(self.url,
                                    auth=requests.auth.HTTPBasicAuth(
                                                self.username, self.password),
                                    headers=self.headers,
                                    verify=False)
        self.debug_print("Return Status Code {0}".format(result.status_code))
        return result

    def validate_ip(self):
        ip_net = ''
        try:
            ip_net = IPNetwork(self.destination_network)
        except:
            return False
        if ip_net.prefixlen in range(32) and (ip_net.network != ip_net.ip):
            self.destination_network = "{0}/{1}".format(ip_net.network,
                                                        ip_net.prefixlen)
        return True

    def _gen_Network_Dict(self):
        ip_and_mask = self.destination_network.split('/')
        if len(ip_and_mask) == 1 or int(ip_and_mask[1]) == 32:
            self.debug_print("IP is type Host")
            self.destination_dict = {u'type': u'Host',
                                     u'value': u'{0}'.format(
                                                self.destination_network)}
        elif len(ip_and_mask) == 2 and int(ip_and_mask[1]) in range(32):
            self.debug_print("IP is type Network")
            self.destination_dict = {u'type': u'Network',
                                     u'value': u'{0}'.format(
                                                self.destination_network)}
        self.debug_print("_gen_Network_Dict: "
                         "{0}".format(self.destination_dict))
        if self.destination_network:
            return True
        else:
            return False

    def _deploy_config(self):
        # Add an action result to the App Run
        action_result = ActionResult()
        self.add_action_result(action_result)

        self._get_Firepower_Deployable_Devices()

        print self.firepower_deployable_devices
        deployable_device_UUIDs = [device['id'] for device in
                                   self.firepower_deployable_devices]

        self.api_path = ("/api/fmc_config/v1/domain/"
                         "{0}/deployment/deploymentrequests".format(
                                                            self.domain_uuid))
        self.debug_print("api_path: {0}".format(self.api_path))

        self.js = {'type': 'DeploymentRequest',
                   'version': '0',
                   'forceDeploy': True,
                   'ignoreWarning': True,
                   'deviceList': (deployable_device_UUIDs)}
        self.debug_print("self.js: {0}".format(self.js))
        # Go get er!
        api_response = self.api_run('post', self.api_path)
        resp = api_response.text
        json_resp = json.loads(resp)
        self.debug_print("Deployment result RAW:"
                         "{0}".format(json.dumps(json_resp, indent=4)))
        if api_response.status_code in [200, 202]:
            action_result.set_status(phantom.APP_SUCCESS,
                                     "Successfully deployed {0}".format(
                                                    self.destination_network))
        else:
            summary = {'message': "Failed to deploy"}
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_ERROR,
                                     ("ERROR: " "{0}".format(
                                        json_resp['error']
                                        ['messages'][0]['description'])))
            return
        try:
            self.network_group_list = json_resp['literals']
            self.debug_print("Network Group Object result: {0}".format(
                                                self.network_group_list))
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
        return action_result.get_status()

    def _test_connectivity(self, param):
        """
        Called when the user depresses the test connectivity
        button on the Phantom UI.
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.debug_print("%s TEST_CONNECTIVITY %s" % (FP_Connector.BANNER,
                                                      param))

        # Set configuration variables from json
        self._get_Config(param)

        self._get_token()
        if self.token:
            self.debug_print("RECEIVED TOKEN: {0}".format(self.token))
            self.set_status_save_progress(phantom.APP_SUCCESS,
                                          "SUCCESS! Received token"
                                          "from device")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.debug_print("DIDN'T RECEIVE TOKEN: BAD THINGS HAPPENED")
            self.set_status_save_progress(phantom.APP_ERROR,
                                          "FAILURE! Unable to obtain "
                                          "token from device")
            return action_result.set_status(phantom.APP_ERROR)

    def listNetworksInObject(self, param):
        """
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Set configuration variables from json
        self._get_Config(param)

        # Initializes the current networks and sets the URL
        self._get_Group_Object_Networks()

        # Even if the query was successfull data might not be available
        if not self.network_group_list:
            return action_result.set_status(phantom.APP_ERROR,
                                            "API Request returned no data")
        if self.network_group_list:
            for net in self.network_group_list:
                action_result.add_data(
                        {'network': net['value']})
            summary = {'message': "Query returned " +
                       "{0} routes".format(len(self.network_group_list))}
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
            self.set_status_save_progress(phantom.APP_SUCCESS,
                                          "Query returned"
                                          "{0} routes".format(
                                                action_result.get_data_size))
        else:
            action_result.set_status(phantom.APP_SUCCESS, "Success")

        return action_result.get_status()

    def addToNetworkObject(self, param):
        """
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.debug_print(param)

        # Set configuration variables from json
        self._get_Config(param)
        # Initializes the current networks and sets the URL
        self._get_Group_Object_Networks()

        try:
            self.destination_network = param['ip']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
        self.debug_print("Network: {0}".format(self.destination_network))
        if self.validate_ip():
            self._gen_Network_Dict()
        else:
            return action_result.set_status(phantom.APP_ERROR,
                                            "IP not valid:"
                                            "{0}".format(
                                                param["destination-network"]))
        self.network_group_list.append(self.destination_dict)

        self.js = {u'id': self.netgroup_uuid,
                   u'name': self.network_group_object,
                   u'literals': (self.network_group_list)}
        self.debug_print("self.js: {0}".format(self.js))
        # Go get er!
        api_response = self.api_run('put', self.api_path)
        if api_response:
            action_result.set_status(phantom.APP_SUCCESS,
                                     "Successfully added {0}".format(
                                                    self.destination_network))
        else:
            action_result.set_status(phantom.APP_ERROR)
        # Commented out until Cisco resolves TAC case
        self._deploy_config()
        return action_result.get_status()

    def delFromNetworkObject(self, param):
        """
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.debug_print(param)

        # Set configuration variables from json
        self._get_Config(param)

        # Initializes the current networks and sets the URL
        self._get_Group_Object_Networks()

        try:
            self.destination_network = param['ip']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

        self.debug_print("Network: {0}".format(self.destination_network))

        if self.validate_ip():
            self._gen_Network_Dict()
        else:
            return action_result.set_status(phantom.APP_ERROR,
                                            "IP not valid: {0}".format(
                                                param["destination-network"]))

        self.network_group_list.remove(self.destination_dict)

        self.js = {u'id': self.netgroup_uuid,
                   u'name': self.network_group_object,
                   u'literals': (self.network_group_list)}
        self.debug_print("self.js: {0}".format(self.js))
        # Go get er!
        api_response = self.api_run('put', self.api_path)
        if api_response:
            action_result.set_status(phantom.APP_SUCCESS,
                                     "Successfully deleted {0}".format(
                                                self.destination_network))
        else:
            # TODO: Figure out how to send a good error if the route
            # already exists (404 error)
            action_result.set_status(phantom.APP_ERROR)
        # Commented out until Cisco resolves TAC case
        self._deploy_config()
        return action_result.get_status()

    def handle_action(self, param):
        """
        This function implements the main functionality of the AppConnector.
        It gets called for every param dictionary element in the parameters
        array. In it's simplest form it gets the current action identifieri
        and then calls a member function of it's own to handle the action.
        This function is expected to create the results of the action run
        that get added to the connector run. The return value of this function
        is mostly ignored by the BaseConnector. Instead it will just loop
        over the next param element in the parameters array and call
        handle_action again.

        We create a case structure in Python to allow for any number of
        actions to be easily added.
        """
        # action_id determines what function to execute
        action_id = self.get_action_identifier()
        self.debug_print("%s HANDLE_ACTION action_id:%s parameters:\n%s"
                         % (FP_Connector.BANNER, action_id, param))

        supported_actions = {"test connectivity": self._test_connectivity,
                             "list_networks": self.listNetworksInObject,
                             "block_ip": self.addToNetworkObject,
                             "unblock_ip": self.delFromNetworkObject
                             }

        run_action = supported_actions[action_id]

        return run_action(param)


# =============================================================================
# Logic for testing interactively e.g.
# python2.7 ./cisco_firepowerr_connector.py ./test_jsons/test.json
# If you don't reference your module with a "./" you will encounter a 'failed
# to load app json'
# =============================================================================

if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    # input a json file that contains data like the configuration and action
    # parameters
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print ("%s %s" % (sys.argv[1], json.dumps(in_json, indent=4)))

        connector = FP_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ("%s %s" % (connector.BANNER,
                          json.dumps(json.loads(ret_val), indent=4)))

    exit(0)
