# -*- coding: utf-8 -*-

'''
This module provides an easy way to script administration tasks
to manage Hitachi Data Instance Director (HDID) or Hitachi Ops
Center Protector.

This module requires Python 3.6+
'''

import sys
import json
import requests


class HDID():
    """Represents a Hitachi Data Instance Director Instance and
       exposes administrative APIs.
    """

    def __init__(self, target, username=None, password=None,
                 space=None, dest_node=None, verify_https=False,
                 ssl_cert=None, user_agent=None, request_kwargs=None):

        self._cookies = {}
        self._headers = {"Content-Type": "application/json"}
        self._target = target
        self._dest_node = dest_node

        self._request_kwargs = dict(request_kwargs or {})
        if "verify" not in self._request_kwargs:
            if ssl_cert and verify_https:
                self._request_kwargs['verify'] = ssl_cert
            else:
                self._request_kwargs['verify'] = verify_https

        self._user_agent = user_agent
        if self._user_agent:
            self._headers['User-Agent'] = self._user_agent
        auth = 'Session_ID=' + (self._obtain_api_session(
            username, password, space))
        self._headers['Cookie'] = auth

    def _format_path(self, path):
        return f'https://{self._target}/HDID/{path}'

    def _request(self, method, path, data=None):
        """Perform HTTP request for REST API."""
        if path.startswith("http"):
            url = path  # For cases where URL of different form is needed.
        else:
            url = self._format_path(path)

        if not data:
            try:
                response = requests.request(method, url,
                                            headers=self._headers,
                                            cookies=self._cookies,
                                            **self._request_kwargs)
            except requests.exceptions.RequestException as err:
                raise HDIDError(err)
        else:
            body = json.dumps(data).encode("utf-8")
            try:
                response = requests.request(method, url, data=body,
                                            headers=self._headers,
                                            cookies=self._cookies,
                                            **self._request_kwargs)
                print(url)
            except requests.exceptions.RequestException as err:
                raise HDIDError(err)

        if response.status_code >= 400:
            print(f'\nAPI failed with status code {response.status_code}'
                  f' and {response.text}')
            sys.exit()
        elif response.status_code == 201:
            print(f'\nOperation was Successful {response.text}')
        if response.status_code == 200:
            content = response.json()
            if content:
                try:
                    if isinstance(content, list):
                        content = ResponseList(content)
                    elif isinstance(content, dict):
                        content = ResponseDict(content)
                    content.headers = response.headers
                    return content
                except Exception:
                    print("There is no content to return")
            else:
                pass

    #
    # Session management methods
    #

    def _obtain_api_session(self, username, password, space):
        """Use username, password, and domain space to obtain
           and return an API Session ID."""
        try:
            url = (f'https://{self._target}/HDID/{self._dest_node}'
                   '/UIController/services/User/actions/login/invoke')
            data = requests.request('POST', url,
                                    data={'username': username,
                                          'password': password,
                                          'space': space}, verify=False)
            cookie = data.cookies.get_dict()['Session_ID']
            return cookie
        except KeyError as err:
            print("\nINCORRECT PASSWORD! Use your domain password.", err)
            sys.exit()

    def invalidate_cookie(self):
        """End the REST API session by invalidating
           the current session cookie.

        .. note::
            Calling any other methods again creates a new cookie. This method
            is intended to be called when the HDID object is no longer
            needed.
        """
        self._request('POST', (f'{self._dest_node}/UIController/services/Users/'
                               'actions/logout/invoke'))

    #
    # Authentication (Role-based Access Control) methods
    #

    def list_auth_groups(self, **kwargs):
        """List all RBAC Groups."""
        return self._request('GET', (f'{self._dest_node}/AuthenticationHandler/'
                                     'objects/Groups'), kwargs)

    def get_auth_group(self, grp_id, **kwargs):
        """Return a RBAC Group."""
        return self._request('GET', (f'{self._dest_node}/AuthenticationHandler/'
                                     f'objects/Groups/{grp_id}'), kwargs)

    def list_spaces(self, **kwargs):
        """List all authentication spaces that the authentication handler
           can use for authenticating users."""
        return self._request('GET', (f'{self._dest_node}/AuthenticationHandler/'
                                     'objects/Spaces'), kwargs)

    def get_space(self, space_id, **kwargs):
        """Return a single authentication space."""
        return self._request('GET', (f'{self._dest_node}/AuthenticationHandler/'
                                     f'objects/Spaces/{space_id}'), kwargs)

    def list_users(self, **kwargs):
        """List all RBAC Users."""
        return self._request('GET', (f'{self._dest_node}/AuthenticationHandler/'
                                     'objects/Users'), kwargs)

    def get_user(self, user_id, **kwargs):
        """Return a single authentication space."""
        return self._request('GET', (f'{self._dest_node}/AuthenticationHandler/'
                                     f'objects/Users/{user_id}'), kwargs)

    #
    # Authorization (Access Control Profile) methods
    #

    def list_access_levels(self, **kwargs):
        """List all RBAC Access Levels."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/AccessLevels'), kwargs)

    def get_access_level(self, access_id, **kwargs):
        """Return a single RBAC Access Level."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/AccessLevels/{access_id}'), kwargs)

    def list_acp_assoc(self, **kwargs):
        """List all Domain/Group/User associated to RBAC ACPs."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/ACPAssociations'), kwargs)

    def get_acp_assoc(self, acp_id, **kwargs):
        """Return a single Domain/Group/User associated to a RBAC ACP."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ACPAssociations/{acp_id}'), kwargs)

    def get_acp_grant(self, acp_id, **kwargs):
        """Return a single ACP that the association grants."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ACPAssociations/{acp_id}/collections/acps'),
                             kwargs)

    def create_acp_assoc(self, name, **kwargs):
        """Create a single Domain/Group/User associated to a RBAC ACP.

           :param name: Name of the Domain User.
           :type name: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **POST objects/ACPAssociations**
           :type **kwargs: optional

        """
        data = {
            "name": name
        }
        data.update(kwargs)
        return self._request('POST', (f'{self._dest_node}/AuthorizationHandler/'
                                      'objects/ACPAssociations'), data)

    def set_acp_grant(self, user_id, acp_id, **kwargs):
        """Assign ACP to a Profile.

           :param user_id: ID of the HDID Domain User.
           :type user_id: str
           :param acp_id: ACP Association id.
           :type acp_id: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **PUT objects/ACPAssociations**
           :type **kwargs: optional
        """
        data = {"id": [acp_id]}
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ACPAssociations/{user_id}/collections/acps'),
                             data)

    def list_acp_assoc_summary(self, **kwargs):
        """List all RBAC summaries for ACP associations."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/ACPAssociationSummaries'), kwargs)

    def get_acp_assoc_summary(self, assoc_id, **kwargs):
        """Return a single RBAC summary for an ACP association."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ACPAssociationSummaries/{assoc_id}'),
                             kwargs)

    def list_acps(self, **kwargs):
        """List all ACPs."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/ACPS'), kwargs)

    def get_acp(self, acp_id, **kwargs):
        """Return a single ACP."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ACPAssociationSummaries/{acp_id}'),
                             kwargs)

    def list_act(self, **kwargs):
        """List all RBAC Activities."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/Activities'), kwargs)

    def get_act(self, act_id, **kwargs):
        """Return a single RBAC Activity."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/Activities/{act_id}'), kwargs)

    def list_act_grps(self, **kwargs):
        """List all RBAC Activity Groups."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/ActivityGroups'), kwargs)

    def get_act_grp(self, act_gid, **kwargs):
        """Return a single RBAC Activity Group."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ActivityGroups/{act_gid}'), kwargs)

    def list_res_grps(self, **kwargs):
        """List all RBAC Resource Groups."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/ResourceGroups'), kwargs)

    def get_res_grp(self, res_gid, **kwargs):
        """Return a single RBAC Resource Group."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ResourceGroups/{res_gid}'), kwargs)

    def list_usr_res_grps(self, **kwargs):
        """List all RBAC User Resource Groups."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'services/ResourceGroups/actions/'
                                     'getusersresourcegroups/invoke'), kwargs)

    def get_usr_res_coll(self, usr_res_gid, **kwargs):
        """Return the resources contained in this Resource Group."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/ResourceGroups/{usr_res_gid}/'
                                     'collections/resources'), kwargs)

    def list_res(self, **kwargs):
        """List all RBAC Resources."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/Resources'), kwargs)

    def get_res(self, res_id, **kwargs):
        """Return a single RBAC Resource."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/Resources/{res_id}'), kwargs)

    def list_roles(self, **kwargs):
        """List all RBAC Roles."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     'objects/Roles'), kwargs)

    def get_role(self, role_id, **kwargs):
        """Return a single RBAC Role."""
        return self._request('GET', (f'{self._dest_node}/AuthorizationHandler/'
                                     f'objects/Roles/{role_id}'), kwargs)

    #
    # DataFlowHandler methods
    #

    def list_active_dataflows(self, **kwargs):
        """Return a list of dictionaries describing each active dataflow.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET ActiveDataflows**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/DataflowHandler/'
                                     'objects/ActiveDataflows'), kwargs)

    def get_active_dataflow(self, df_id, **kwargs):
        """Return a single active dataflow.

        :param df_id: ID of Active DataFlow for which to list information.
        :type df_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET ActiveDataflows**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/DataflowHandler/'
                                     f'objects/ActiveDataflows/{df_id}'), kwargs)

    def list_dataflows(self, **kwargs):
        """Return a list of dictionaries describing each dataflow.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Dataflows**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/DataflowHandler/'
                                     'objects/Dataflows'), kwargs)

    def get_dataflow(self, df_id, **kwargs):
        """Return a single dataflow.

        :param df_id: ID of DataFlow for which to list information.
        :type df_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Dataflows**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/DataflowHandler/'
                                     f'objects/Dataflows/{df_id}'), kwargs)

    def set_dataflow(self, df_id, **kwargs):
        """Modify a single dataflow.

           :param df_id: ID of DataFlow to modify.
           :type df_id: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **PUT objects/Dataflows**
           :type **kwargs: optional
        """
        data = {"data":
                {"id": df_id}
                }
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/DataflowHandler/'
                                     f'objects/Dataflows/{df_id}'), data)

    def create_dataflow(self, df_name, **kwargs):
        """Create a dataflow.

           :param df_name: Name of the new DataFlow.
           :type df_name: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **POST objects/Dataflows**
           :type **kwargs: optional
        """
        data = {"data":
                {"name": df_name}
                }
        data.update(kwargs)
        return self._request('POST', (f'{self._dest_node}/DataflowHandler/'
                                      'objects/Dataflows/'), data)

    def delete_dataflow(self, df_id, **kwargs):
        """Delete a dataflow.

           :param df_id: ID of the DataFlow to delete.
           :type df_id: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **DELETE objects/Dataflows**
           :type **kwargs: optional
        """
        return self._request('DELETE', (f'{self._dest_node}/DataflowHandler/'
                                        f'objects/Dataflows/{df_id}'), kwargs)

    def list_dest_tmpl(self, **kwargs):
        """Return a list of dictionaries describing each destination template.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET DestinationTemplates**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/DataflowHandler/'
                                     'objects/DestinationTemplates'), kwargs)

    def get_dest_tmpl(self, tmpl_id, **kwargs):
        """Return a single destination template.

        :param tmpl_id: ID of the Template for which to list information.
        :type tmpl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET DestinationTemplates**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/DataflowHandler/'
                                     f'objects/DestinationTemplates/{tmpl_id}'),
                             kwargs)

    #
    # HardwareNodeHandler methods
    #

    def list_hdw_nodes(self, **kwargs):
        """Return the configuration of all hardware agentless nodes.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET HardwareNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/HardwareNodeHandler/'
                                     'objects/HardwareNodes'), kwargs)

    def get_hdw_node(self, hdw_id, **kwargs):
        """Return the configuration of a single hardware agentless node.

        :param hdw_id: ID of the hardware node for which to list information.
        :type hdw_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET HardwareNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/HardwareNodeHandler/'
                                     f'objects/HardwareNodes/{hdw_id}'), kwargs)

    def create_hdw_node(self, hbh, src_node_id, **kwargs):
        """Create a hardware block node.

           :param hbh: Label of the new Block node.
           :type hbh: str
           :param src_node_id: ID of the Source Storage System.
           :type sn: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **POST objects/HardwareNodes**
           :type **kwargs: optional
        """
        data = {"name": hbh,
                "resourceGroup": "1",
                "hostNode": src_node_id,
                "nodeType": "HardwareNodeBlock"
                }
        data.update(kwargs)
        return self._request('POST', (f'{self._dest_node}/HardwareNodeHandler/'
                                      'objects/HardwareNodes'), data)

    def delete_hdw_node(self, hbh_id, **kwargs):
        """Delete a hardware block node.

           :param hbh_id: ID of the Hardware Block node.
           :type hbh_id: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **DELETE objects/HardwareNodes**
           :type **kwargs: optional
        """
        return self._request('DELETE', (f'{self._dest_node}/HardwareNodeHandler/'
                                        f'objects/HardwareNodes/{hbh_id}'), kwargs)

    def set_hdw_node(self, hbh_id, src_node_id, **kwargs):
        """Modify a hardware block node.

           :param hbh_id: ID of the Block node.
           :type hbh_id: str
           :param src_node_id: ID of the Source Storage System.
           :type sn: str

           :param **kwargs: See the REST API Guide for the
                              documentation on the request:
                              **PUT objects/HardwareNodes**
           :type **kwargs: optional
        """
        data = {"id": hbh_id,
                "resourceGroup": "1",
                "hostNode": src_node_id,
                "nodeType": "HardwareNodeBlock"
                }
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/HardwareNodeHandler/'
                                     f'objects/HardwareNodes/{hbh_id}'), data)

    #
    # JobStatusHandler methods
    #

    def list_jobs(self, **kwargs):
        """Return the jobs being carried out by the system.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Jobs**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/JobStatusHandler/'
                                     'objects/Jobs'), kwargs)

    def get_job(self, job_id, **kwargs):
        """Return a single job being carried out by the system.

        :param job_id: ID of the job for which to list information.
        :type job_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Jobs**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/JobStatusHandler/'
                                     f'objects/Jobs/{job_id}'), kwargs)

    def list_jobsubs(self, **kwargs):
        """Return the allowed job subsystems.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET JobSubSystems**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/JobStatusHandler/'
                                     'objects/JobSubSystems'), kwargs)

    def get_jobsub(self, sub_name, **kwargs):
        """Return a single job subsystem.

        :param sub_name: job subsystem name for which to list information.
        :type df_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET JobSubSystems**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/JobStatusHandler/'
                                     f'objects/JobSubSystems/{sub_name}'),
                             kwargs)

    def list_jobtypes(self, **kwargs):
        """Return the allowed job subtypes.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET JobSubTypes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/JobStatusHandler/'
                                     'objects/JobSubTypes'), kwargs)

    def get_jobtype(self, type_name, **kwargs):
        """Return a single job subtype.

        :param type_name: job subtype name for which to list information.
        :type type_name: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET JobSubTypes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/JobStatusHandler/'
                                     f'objects/JobSubTypes/{type_name}'), kwargs)

    #
    # NodeManager methods
    #

    def list_cifs_nodes(self, **kwargs):
        """Return the configuration of a CIFS agentless node.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET CIFSAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     'objects/CIFSAgentlessNodes'), kwargs)

    def get_cifs_node(self, node, **kwargs):
        """Return a single CIFS agentless node.

        :param node: CIFS node name for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET CIFSAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'objects/CIFSAgentlessNodes/{node}'),
                             kwargs)

    def list_hvsp_nodes(self, **kwargs):
        """Return the configuration of a Hitachi block storage agentless node.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET HVSPAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     'objects/HVSPAgentlessNodes'), kwargs)

    def get_hvsp_node(self, node, **kwargs):
        """Return a single Hitachi block storage agentless node.

        :param node: Hitachi VSP node name for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET HVSPAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'objects/HVSPAgentlessNodes/{node}'),
                             kwargs)

    def list_lvsp_nodes(self, **kwargs):
        """Return the configuration of logical VSP agentless nodes.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET LogicalVSPAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     'objects/LogicalVSPAgentlessNodes'),
                             kwargs)

    def get_lvsp_node(self, node, **kwargs):
        """Return a single logical VSP agentless node.

        :param node: Logical VSP node name for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET LogicalVSPAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'objects/LogicalVSPAgentlessNodes/{node}'),
                             kwargs)

    def list_nodes(self, **kwargs):
        """Return the configuration of all nodes.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Nodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     'objects/Nodes'), kwargs)

    def get_node(self, node, **kwargs):
        """Return a single node.

        :param node: Node name for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Nodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'objects/Nodes/{node}'), kwargs)

    def list_node_types(self, **kwargs):
        """Return the description of all node types.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET NodeTypes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     'objects/NodeTypes'), kwargs)

    def get_node_type(self, node_type, **kwargs):
        """Return the description of a single node type.

        :param node_type: Node type for which to list information.
        :type node_type: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET NodeTypes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'objects/NodeTypes/{node_type}'),
                             kwargs)

    def list_repo_nodes(self, **kwargs):
        """Return the configuration of all HDID repository agentless nodes.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET RepositoryAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     'objects/RepositoryAgentlessNodes'),
                             kwargs)

    def get_repo_node(self, node, **kwargs):
        """Return the configuration of a HDID repository agentless node.

        :param node: Repository node for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET RepositoryAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'objects/RepositoryAgentlessNodes/{node}'),
                             kwargs)

    def list_esx_nodes(self, **kwargs):
        """Return the configuration of all VMware ESX agentless nodes.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET VMwareESXAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     '/objects/VMwareESXAgentlessNodes'),
                             kwargs)

    def get_esx_node(self, node, **kwargs):
        """Return the configuration of a VMware ESX agentless node.

        :param node: VMware ESX node for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET VMwareESXAgentlessNodes**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/NodeManager/'
                                     f'/objects/VMwareESXAgentlessNodes/{node}'),
                             kwargs)

    #
    # TriggerHandler methods
    #

    def list_triggers(self, **kwargs):
        """Return the handler for triggering replications.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Triggers**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/TriggerHandler/'
                                     'objects/Triggers'), kwargs)

    def get_trigger(self, trig_id, **kwargs):
        """Return a single trigger.

        :param trig_id: Trigger ID for which to list information.
        :type node: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Triggers**
        """
        return self._request('GET', (f'{self._dest_node}/TriggerHandler/'
                                     f'objects/Triggers/{trig_id}'), kwargs)

    def trigger_repl(self, src_node_id, des_node_id, **kwargs):
        """Trigger replication process for a data flow.

        :param src_node_id: ID of the Source Node.

        :type src_node_id: str
        :param des_node_id: ID of the Destination Node.

        :type src_node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Rules**
        :type **kwargs: optional
        """
        data = {
            "sourceNodeId": src_node_id,
            "destinationNodeId": des_node_id
        }
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/TriggerHandler/'
                                     'services/Triggers/actions/'
                                     'triggeroperation/invoke'), data)

    #
    # PolicyHandler methods
    #

    def list_class(self, **kwargs):
        """Return all items in the policy definition classification palette.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Classifications**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/PolicyHandler/'
                                     'objects/Classifications'), kwargs)

    def get_class(self, class_id, **kwargs):
        """Return a single policy classification.

        :param class_id: Classification ID for which to list information.
        :type class_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Classifications**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/PolicyHandler/'
                                     f'objects/Classifications/{class_id}'),
                             kwargs)

    def list_ops(self, **kwargs):
        """Return all items in the policy definition operations palette.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Classifications**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/PolicyHandler/'
                                     'objects/Operations'), kwargs)

    def get_op(self, op_id, **kwargs):
        """Return a single policy operation.

        :param op_id: Operations ID for which to list information.
        :type op_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Classifications**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/PolicyHandler/'
                                     f'objects/Operations/{op_id}'), kwargs)

    def list_policies(self, **kwargs):
        """Return all policies.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Policies**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/PolicyHandler/'
                                     'objects/Policies'), kwargs)

    def get_policy(self, policy_id, **kwargs):
        """Return a single policy.

        :param policy_id: Policy ID for which to list information.
        :type policy_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Policies**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/PolicyHandler/'
                                     f'objects/Policies/{policy_id}'), kwargs)

    #
    # RulesManager methods
    #

    def compile_rules(self, df_id, **kwargs):
        """Compile a DataFlow or DataFlows into rules.

        :param df_id: ID of the DataFlow to compile.
        :type df_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Rules**
        :type **kwargs: optional

        Note:
            Body requires: {ids: ['ca02a40e-a495-4937-8b07-8968c5d28724']}
        """
        data = {"ids": [df_id]}
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/RulesManager/services/'
                                     'Rules/actions/compile/invoke'), data)

    def dist_rules(self, df_id, **kwargs):
        """Distribute the given data flows, distribute their latest rules.

        :param df_id: ID of the DataFlow to distribute rules.
        :type df_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Rules**
        :type **kwargs: optional
        """
        data = {"ids": [df_id]}
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/RulesManager/services/'
                                     'Rules/actions/distribute/invoke'), data)

    def deact_rules(self, df_id, **kwargs):
        """Deactivate the given data flows, remove them from the rules.

        :param df_id: ID of the DataFlow to deactivate.
        :type df_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Rules**
        :type **kwargs: optional
        """
        data = {"ids": [df_id]}
        data.update(kwargs)
        return self._request('PUT', (f'{self._dest_node}/RulesManager/services/'
                                     '/Rules/actions/deactivate/invoke'), data)

    #
    # ServicesManager methods
    #

    def list_svcs(self, **kwargs):
        """Return all services.

        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Services**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/ServicesManager/'
                                     'objects/Services'), kwargs)

    def get_svc(self, service_id, **kwargs):
        """Return a single service.

        :param service_id: Service ID for which to list information.
        :type service_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Services**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{self._dest_node}/ServicesManager/'
                                     f'objects/Services/{service_id}'), kwargs)

    #
    # VirtualStoragePlatformHandler methods
    #

    def get_hostgrps(self, node_id, **kwargs):
        """Return all HostGroups that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET HostGroups**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/HostGroups'), kwargs)

    def list_hostgrps(self, node_id, **kwargs):
        """Return all HostGroups that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET HostGroups**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/HostGroups'), kwargs)

    def refresh_prop(self, node_id, **kwargs):
        """Allows a user to refresh the cache of details
           on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to refresh.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Properties**
        :type **kwargs: optional
        """
        return self._request('PUT', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'services/Properties/actions/refresh/invoke'),
                             kwargs)

    def list_jnls(self, node_id, **kwargs):
        """Return all Journals that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Journals**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/Journals'), kwargs)

    def list_ldevs(self, node_id, **kwargs):
        """Return all Logical Devices that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET LogicalDevices**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/LogicalDevices'), kwargs)

    def list_pools(self, node_id, **kwargs):
        """Return all Pools that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Pools**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/Pools'), kwargs)

    def list_props(self, node_id, **kwargs):
        """Return all Properties that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Properties**
        :type **kwargs: optional

        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/Properties'), kwargs)

    def list_quorums(self, node_id, **kwargs):
        """Return all Quorums that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Quora**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/Quora'), kwargs)

    def list_repls(self, node_id, **kwargs):
        """Return all Replication jobs that belong to a storage system.

        :param node_id: HDID Node ID for which to list information.
        :type node_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET Replications**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     'objects/Replications'), kwargs)

    def pause_repl(self, node_id, repl_id, **kwargs):
        """Allows a user to pause a Hardware Replication stored
           on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to pause replication.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Pause**
        :type **kwargs: optional
        """
        return self._request('PUT', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/actions/'
                                     "pause/invoke"), kwargs)

    def resume_repl(self, node_id, repl_id, **kwargs):
        """Allows a user to resume a paused Hardware Replication stored
           on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to resume replication.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT Resume**
        :type **kwargs: optional
        """
        return self._request('PUT', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/actions/'
                                     'resume/invoke'), kwargs)

    def repl_resources(self, node_id, repl_id, **kwargs):
        """Allows a user to view the resources of a Hardware Replication
           stored on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to view resources.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET hardwareresources**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/actions/'
                                     'hardwareresources/invoke'), kwargs)

    def dissociate_repl(self, node_id, repl_id, **kwargs):
        """Allows a user to discard an active Hardware Replication
           stored on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to dissociate.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **DELETE dissociate**
        :type **kwargs: optional
        """
        return self._request('DELETE', (f'{node_id}/VirtualStoragePlatformHandler/'
                                        f'objects/Replications/%7B{repl_id}%7D/actions/'
                                        'dissociate/invoke'), kwargs)

    def unsuspend_repl(self, node_id, repl_id, **kwargs):
        """Allows a user to unsuspend a suspended Hardware Replication
           stored on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to unsuspend.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT unsuspend**
        :type **kwargs: optional
        """
        return self._request('PUT', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/actions/'
                                     'unsuspend/invoke'), kwargs)

    def rename_svol(self, node_id, repl_id, **kwargs):
        """Allows a user to rename a secondary logical device
           stored on a Hitachi Virtual Storage platform.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to unsuspend.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **PUT renamesecondarylogicaldevices**
        :type **kwargs: optional
        """
        return self._request('PUT', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/actions/'
                                     'renamesecondarylogicaldevices/invoke'),
                             kwargs)

    def repl_ldevs(self, node_id, repl_id, **kwargs):
        """LDEVs used in this replication, derived from replication
           statistics if available, and stored data if not.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to get replicated ldevs.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET logicaldevices**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/'
                                     'collections/logicaldevices'), kwargs)

    def repl_pairs(self, node_id, repl_id, **kwargs):
        """Pairs used in this replication, derived from replication
           statistics if available, and stored data if not.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to get replicated pairs.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET pairs**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/'
                                     'collections/pairs'), kwargs)

    def repl_jnls(self, node_id, repl_id, **kwargs):
        """Journals used in this replication, derived from replication
           statistics if available, and stored data if not.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to get journal info.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET journals**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/'
                                     'collections/journals'), kwargs)

    def repl_pools(self, node_id, repl_id, **kwargs):
        """Pools used in this replication, derived from replication
           statistics if available, and stored data if not.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to get pool info.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET pools**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/'
                                     'collections/pools'), kwargs)

    def repl_svols(self, node_id, repl_id, **kwargs):
        """Secondary logical devices created by the replication.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to get S-VOL info.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET secondarylogicaldevices**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/'
                                     'collections/secondarylogicaldevices'), kwargs)

    def repl_hostgrps(self, node_id, repl_id, **kwargs):
        """Host groups used in this replication, derived from replication
           statistics if available, and stored data if not.

        :param node_id: HDID Node ID for which to take action.
        :type node_id: str
        :param repl_id: Replication ID for which to get hostgroup info.
        :type repl_id: str
        :param **kwargs: See the REST API Guide for the
                           documentation on the request:
                           **GET hostgroups**
        :type **kwargs: optional
        """
        return self._request('GET', (f'{node_id}/VirtualStoragePlatformHandler/'
                                     f'objects/Replications/%7B{repl_id}%7D/'
                                     '/collections/hostgroups'), kwargs)


class ResponseList(list):
    """List type returned by HDID object.

    :ivar dict headers: The headers returned in the request.
    """

    def __init__(self, li=()):
        super(ResponseList, self).__init__(li)
        self.headers = {}


class ResponseDict(dict):
    """Dict type returned by HDID object.

    :ivar dict headers: The headers returned in the request.
    """

    def __init__(self, di=()):
        super(ResponseDict, self).__init__(di)
        self.headers = {}


class HDIDError(Exception):
    """Exception type raised by HDID object.

    :param reason: A message describing why the error occurred.
    :type reason: str

    :ivar str reason: A message describing why the error occurred.
    """

    def __init__(self, reason):
        self.reason = reason
        super(HDIDError, self).__init__()

    def __str__(self):
        return f'HDIDError: {self.reason}'
