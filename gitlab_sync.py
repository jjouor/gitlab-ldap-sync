#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error,no-member

import os
import logging
import datetime
from xml.sax import parse

import gitlab
import ldap
import ldap.asyncsearch
import re

logging.basicConfig(level=logging.INFO)


class GitlabSync:
    """
    Sync gitlab users/groups with freeipa ldap
    """
    def __init__(self):
        sync_dry_run_env = os.getenv('SYNC_DRY_RUN')
        self.sync_dry_run = sync_dry_run_env if sync_dry_run_env else ''
        gitlab_api_url_env = os.getenv('GITLAB_API_URL')
        self.gitlab_api_url = gitlab_api_url_env if gitlab_api_url_env else ''
        gitlab_token_env = os.getenv('GITLAB_TOKEN')
        self.gitlab_token = gitlab_token_env if gitlab_token_env else ''
        gitlab_ldap_provider_env = os.getenv('GITLAB_LDAP_PROVIDER')
        self.gitlab_ldap_provider = gitlab_ldap_provider_env if gitlab_ldap_provider_env else 'ldapmain'
        ldap_url_env = os.getenv('LDAP_URL')
        self.ldap_url = ldap_url_env if ldap_url_env else ''
        ldap_users_base_dn_env = os.getenv('LDAP_USERS_BASE_DN')
        self.ldap_users_base_dn = ldap_users_base_dn_env if ldap_users_base_dn_env else ''
        ldap_group_base_dn_env = os.getenv('LDAP_GROUP_BASE_DN')
        self.ldap_group_base_dn = ldap_group_base_dn_env if ldap_group_base_dn_env else ''
        ldap_bind_dn_env = os.getenv('LDAP_BIND_DN')
        self.ldap_bind_dn = ldap_bind_dn_env if ldap_bind_dn_env else ''
        ldap_password_env = os.getenv('LDAP_PASSWORD')
        self.ldap_password = ldap_password_env if ldap_password_env else ''
        ldap_gitlab_users_group_env = os.getenv('LDAP_GITLAB_USERS_GROUP')
        self.ldap_gitlab_users_group = ldap_gitlab_users_group_env if ldap_gitlab_users_group_env else 'gitlab-users'
        ldap_gitlab_admin_group_env = os.getenv('LDAP_GITLAB_ADMIN_GROUP')
        self.ldap_gitlab_admin_group = ldap_gitlab_admin_group_env if ldap_gitlab_admin_group_env else 'gitlab-admins'
        ldap_gitlab_group_prefix_env = os.getenv('LDAP_GITLAB_GROUP_PREFIX')
        self.ldap_gitlab_group_prefix = ldap_gitlab_group_prefix_env if ldap_gitlab_group_prefix_env else 'gitlab-group-'
        ldap_gitlab_subgroup_prefix_env = os.getenv('LDAP_GITLAB_SUBGROUP_PREFIX')
        self.ldap_gitlab_subgroup_prefix = ldap_gitlab_subgroup_prefix_env if ldap_gitlab_subgroup_prefix_env else 'gitlab-subgroup-'

        # pylint: disable=invalid-name
        self.gl = None
        self.ldap_obj = None
        self.ldap_gitlab_users = {}
        self.user_filter = f"(&(memberof=cn={self.ldap_gitlab_users_group},{self.ldap_group_base_dn}))"
        self.user_filter_with_uid = "(sAMAccountName=%s)"
        self.groups_memberof_filter = f"(memberof=cn=%s,{self.ldap_group_base_dn})"
        self.admin_user_filter = f"(&(memberof=cn={self.ldap_gitlab_admin_group},{self.ldap_group_base_dn}))"

        logging.info('Initialize gitlab-ldap-sync')

    def check_config(self):
        """
        Check if config values are set
        """
        errors = 0
        if not self.gitlab_api_url:
            logging.error("GITLAB_API_URL is empty")
            errors = errors + 1
        if not self.gitlab_token:
            logging.error("GITLAB_TOKEN is empty")
            errors = errors + 1
        if not self.ldap_url:
            logging.error("LDAP_URL is empty")
            errors = errors + 1
        if not self.ldap_users_base_dn:
            logging.error("LDAP_USERS_BASE_DN is empty")
            errors = errors + 1
        if not self.ldap_group_base_dn:
            logging.error("LDAP_GROUP_BASE_DN is empty")
            errors = errors + 1
        if not self.ldap_bind_dn:
            logging.error("LDAP_BIND_DN is empty")
            errors = errors + 1
        if not self.ldap_password:
            logging.error("LDAP_PASSWORD is empty")
            errors = errors + 1
        return errors

    def sync(self):
        """
        Sync gitlab entities
        """
        try:
            is_not_connected = 0
            is_not_connected += self.check_config()
            is_not_connected += self.connect_to_gitlab()
            is_not_connected += self.bind_to_ldap()
            if is_not_connected > 0:
                logging.error("Cannot connect, exit sync class")
                return
            self.sync_ldap_groups()
            self.create_user()
            self.search_all_users_in_ldap()
            self.sync_gitlab_users()
            self.sync_gitlab_groups()
            self.sync_gitlab_subgroups()
        except Exception as expt:  # pylint: disable=broad-exception-caught
            logging.error("Cannot sync, received exception %s", expt)
            return
        logging.info('Complete syncronization')

    def connect_to_gitlab(self):
        """
        Connect to gitlab using token
        """
        logging.info('Connecting to GitLab')
        if self.gitlab_token:
            self.gl = gitlab.Gitlab(url=self.gitlab_api_url,
                                    private_token=self.gitlab_token,
                                    ssl_verify=True)
        if self.gl is None:
            logging.error('Cannot create gitlab object, aborting')
            return 1
        self.gl.auth()
        return 0

    def bind_to_ldap(self):
        """
        Bind to LDAP
        """
        logging.info('Connecting to LDAP')
        if not self.ldap_url:
            logging.error('You should configure LDAP URL')
            return 1

        try:
            self.ldap_obj = ldap.initialize(uri=self.ldap_url)
            self.ldap_obj.simple_bind_s(self.ldap_bind_dn,
                                        self.ldap_password)
        except:  # pylint: disable=bare-except
            logging.error('Error while connecting to ldap')
            return 1
        if self.ldap_obj is None:
            logging.error('Cannot create ldap object, aborting')
            return 1
        return 0

    def search_all_users_in_ldap(self):
        """
        Search users in LDAP using filter
        """
        # pylint: disable=invalid-name
        ldap_users = [ ]
        for dn, user in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=self.user_filter,
                                               attrlist=['sAMAccountName',
                                                         'displayName',
                                                         'userPrincipalName']):
            if 'sAMAccountName' not in user:
                continue
            username = user['sAMAccountName'][0].decode('utf-8')
            mail = user['userPrincipalName'][0].decode('utf-8')
            self.ldap_gitlab_users[username] = {
                'admin': False,
                'displayName': user['displayName'][0].decode('utf-8'),
                'dn': dn,
                'mail': mail
            }

            ldap_users.append(username)
        for dn, user in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=self.admin_user_filter,
                                               attrlist=['sAMAccountName']):
            if 'sAMAccountName' not in user:
                continue
            username = user['sAMAccountName'][0].decode('utf-8')
            if username in self.ldap_gitlab_users:
                self.ldap_gitlab_users[username]['admin'] = True
            else:
                logging.warning(
                    'User %s in admin group but does not have accesss to gitlab',
                    user.username)
        return ldap_users


    def create_user(self):
        ldap_users = self.search_all_users_in_ldap()
        for user in ldap_users:
            gitlab_users = self.get_gitlab_user_by_username(user)
            if not gitlab_users:

                user_email = self.ldap_gitlab_users[user]['mail']
                user_name = self.ldap_gitlab_users[user]['displayName']
                user_dn = self.ldap_gitlab_users[user]['dn']
                logging.info(f"User {user_name} is not exists")
                if not self.sync_dry_run:
                    self.gl.users.create({'email': f'{user_email}',
                                            'password': 's3cur3s3cr3T',
                                            'username': f'{user}',
                                            'name': f'{user_name}',
                                            'provider': f'{self.gitlab_ldap_provider}',
                                            'extern_uid': f'{user_dn}',
                                            'skip_confirmation': 'true'
                                            })
                logging.info (f"User {user_name} successfully created ")



    def is_ldap_user_exist(self, username):
        """
        Search user in LDAP using filter by username
        """
        # pylint: disable=invalid-name
        for _, user in self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                              scope=ldap.SCOPE_SUBTREE,
                                              filterstr=(
                                                  self.user_filter_with_uid % username),
                                              attrlist=['sAMAccountName']):
            if 'sAMAccountName' not in user:
                continue
            return True
        return False

    def ban_user(self, user, reason=''):
        """
        Ban user in gitlab
        """
        if user.state == 'active':
            if not self.sync_dry_run:
                user.ban()
            logging.info(
                'User %s has banned. Reason: %s',
                user.username, reason)

    def delete_user(self, user, reason=''):
        """
        Delete user in gitlab
        """
        if not self.sync_dry_run:
            user.delete()
        logging.info(
            'User %s has deleted. Reason: %s',
            user.username, reason)

    def unban_user(self, user):
        """
        Unban user in gitlab.
        """
        if user.state == 'banned':
            if not self.sync_dry_run:
                user.unban()
            logging.info(
                'User %s unbanned',
                user.username)

    def parse_group_name(self, group_name):
        """
        Parse ldap groups for better comparison with gitlab groups
        and divide into groups and subgroups
        """
        result = {}
        subgroup_pattern = fr"^{self.ldap_gitlab_subgroup_prefix}(.+?)-(.+?)-(?:guest|developer|owner|maintainer|reporter)$"
        group_pattern = fr"^{self.ldap_gitlab_group_prefix}(.+?)-(?:guest|developer|owner|maintainer|reporter)$"
        match_subgroup = re.match(subgroup_pattern, group_name)
        if match_subgroup:
            result['type'] = "subgroup"
            result['mother_group'] = match_subgroup.group(1).replace('-',' ')
            result['group_name'] = match_subgroup.group(2).replace('-', ' ')
            return result
        match_group = re.match(group_pattern, group_name)
        if match_group:
            result['type'] = "group"
            result['group_name'] = match_group.group(1).replace('-', ' ')
            return result
        # Return None or empty dict if no pattern matched
        return result


    def get_ldap_groups(self):
        """
        Get array of LDAP groups for future manipulation
        """
        group_names = [ ]
        for _, group in self.ldap_obj.search_s(base=self.ldap_group_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr='(cn=gtlb*)',
                                               attrlist=['cn', 'description']):
            if 'cn' in group and group['cn']:
                group_name = group['cn'][0].decode('utf-8')
                group_names.append(group_name)
        return group_names


    def get_git_groups(self):
        """
        Get array of GitLab groups for future manipulation
        """
        git_groups = []
        for groups in self.gl.groups.list(all=True):
            groups_name = groups.name.lower()
            git_groups.append(groups_name)
        return git_groups


    def find_non_existed_groups_in_ldap(self ,ldap_group, git_group):
        """
        Find groups that exist in LDAP AD but not in Gitlab
        """
        unique_in_array1 = set(ldap_group) - set(git_group)
        return list(unique_in_array1)


    def create_gitlab_groups(self, group):
        """
        Create gitlab groups and subgroups if it exists in LDAP AD but not in GitLab
        """
        group_type = group['type']
        group_name = group['group_name']
        group_name_path = group_name.replace(' ','-')
        if group_type == "group":
            logging.info(f'create gitlab group: {group_name}')
            if self.sync_dry_run:
                try:
                    self.gl.groups.create({'name': f'{group_name}','path': f'{group_name_path}'})
                except Exception as e:
                    logging.error(e)
        if group_type == "subgroup":
            for git_groups in self.gl.groups.list(all=True):
                if git_groups.name == group['mother_group']:
                    logging.info(f'create gitlab subgroup: {group_name} in {git_groups.name}' )
                    if self.sync_dry_run:
                        try:
                            self.gl.groups.create({'name': f'{group_name}','path': f'{group_name_path}', 'parent_id': git_groups.id})
                        except Exception as e:
                            logging.error(e)

    def sync_ldap_groups(self):
        """
        Sync groups and subgroups from LDAP AD to GitLab
        """
        logging.info('Getting non-existing groups in GitLab')
        ldap_group_names = [ ]
        ldap_groups = self.get_ldap_groups()
        git_groups_name = self.get_git_groups()
        for group in ldap_groups:
            g = self.parse_group_name(group)
            if 'group_name' in g:
                ldap_group_names.append(g['group_name'])
        uniq = self.find_non_existed_groups_in_ldap(ldap_group_names, git_groups_name )
        if uniq:
            logging.info(f'This Groups in not exist in GitLab {uniq}')
            logging.info('Start creating groups...')
            for uniq_group in uniq:
                for group in ldap_groups:
                    g = self.parse_group_name(group)
                    if 'group_name' in g:
                        if g['group_name'] == uniq_group:
                            print (self.create_gitlab_groups(g))
        else:
            logging.info('All groups already exist')
            logging.info('Continue...')


    def sync_gitlab_users(self):
        """
        Sync users in gitlab.
        """
        for user in self.gl.users.list(all=True):
            if user.bot:
                logging.warning('User %s is bot', user.username)
                continue
            current_ldap_provider_user_dn = ''
            for i in user.identities:
                if i['provider'] == self.gitlab_ldap_provider:
                    current_ldap_provider_user_dn = i['extern_uid']
                    break
            if not current_ldap_provider_user_dn:
                logging.warning('User %s is not managed by ldap %s',
                                user.username, self.gitlab_ldap_provider)
                continue
            logging.warning("Username: %s, LDAP: %s", user.username, self.ldap_gitlab_users) ## Test LDAP
            if user.username not in self.ldap_gitlab_users:
                if self.is_ldap_user_exist(user.username):
                    self.ban_user(
                        user, 'Disabled in ldap or excluded from access group')
                else:
                    self.delete_user(
                        user, 'Deleted in ldap')
                continue

            self.unban_user(user)

            need_to_update_user = False
            if self.ldap_gitlab_users[user.username]['admin'] != user.is_admin:
                logging.info('User %s, update is_admin %s->%s', user.username,
                             user.is_admin, self.ldap_gitlab_users[user.username]['admin'])
                user.admin = self.ldap_gitlab_users[user.username]['admin']
                need_to_update_user = True
            if self.ldap_gitlab_users[user.username]['displayName'] != user.name:
                logging.info('User %s, update name %s->%s', user.username,
                             user.name, self.ldap_gitlab_users[user.username]['displayName'])
                user.name = self.ldap_gitlab_users[user.username]['displayName']
                need_to_update_user = True

            if need_to_update_user:
                logging.info('Saving user %s', user.username)
                if not self.sync_dry_run:
                    user.save()

    def get_gitlab_user_by_username(self, username):
        """
        Return user from gitlab by username
        """
        objects = self.gl.users.list(username=username)
        if len(objects) > 0:
            return objects[0]
        return None

    def fix_gitlab_group_member_access(self, group, member, access_level):
        """
        Fix access level to access_level
        """
        if member['object'].access_level != abs(access_level):
            logging.info("Update access level for %s in group %s: %d->%d",
                         member["username"], group.name, member['object'].access_level, abs(access_level))
            member['object'].access_level = abs(access_level)
            if not self.sync_dry_run:
                member['object'].save()

    def create_gitlab_group_member(self, group, user, level):
        """
        Create member in gitlab group
        """
        if not self.sync_dry_run:
            group.members.create(
                {'user_id': user.id, 'access_level': abs(level)})
        logging.info("Add %s(id=%d) to group %s with level %d",
                     user.username, user.id, group.name, abs(level))

    def remove_gitlab_group_member(self, groupname, user):
        """
        Remove member from gitlab group
        """
        logging.info("Remove %s from group %s",
                     user['username'], groupname)
        if not self.sync_dry_run:
            user['object'].delete()

    def get_ldap_group_access_level_by_name(self, groupname):
        """
        Return access level by group suffix
        """
        if groupname.endswith('-owner'):
            return gitlab.const.OWNER_ACCESS
        if groupname.endswith('-maintainer'):
            return gitlab.const.MAINTAINER_ACCESS
        if groupname.endswith('-developer'):
            return gitlab.const.DEVELOPER_ACCESS
        if groupname.endswith('-reporter'):
            return gitlab.const.REPORTER_ACCESS
        if groupname.endswith('-guest'):
            return gitlab.const.GUEST_ACCESS
        return -gitlab.const.DEVELOPER_ACCESS

    def get_ldap_gitlab_group_members(self, groupname, group_type, mother_group=""):
        """
        Return members from ldap with access levels
        """
        if group_type == 'group':
            gitlab_groups_prefix = f"cn={self.ldap_gitlab_group_prefix}{groupname}"
            gitlab_groups_filter = ''.join([
                "(|",
                f"({gitlab_groups_prefix})",
                f"({gitlab_groups_prefix}-owner)",
                f"({gitlab_groups_prefix}-maintainer)",
                f"({gitlab_groups_prefix}-developer)",
                f"({gitlab_groups_prefix}-reporter)",
                f"({gitlab_groups_prefix}-guest)",
                ")"
            ])
        if group_type == 'subgroup':
            gitlab_subgroups_prefix = f"cn={self.ldap_gitlab_subgroup_prefix}{mother_group}-{groupname}"
            gitlab_groups_filter = ''.join([
                "(|",
                f"({gitlab_subgroups_prefix})",
                f"({gitlab_subgroups_prefix}-owner)",
                f"({gitlab_subgroups_prefix}-maintainer)",
                f"({gitlab_subgroups_prefix}-developer)",
                f"({gitlab_subgroups_prefix}-reporter)",
                f"({gitlab_subgroups_prefix}-guest)",
                ")"
            ])

        # Find all gitlab groups in ldap
        ldap_members = {}
        is_group_exist = False
        for _, group in self.ldap_obj.search_s(base=self.ldap_group_base_dn,
                                               scope=ldap.SCOPE_SUBTREE,
                                               filterstr=gitlab_groups_filter,
                                               attrlist=['cn', 'description']):
            # pylint: disable=invalid-name
            g = group['cn'][0].decode('utf-8')
            # Group is managed by ldap only if ldap has group with name
            # fully equal to gitlab group. If we have testgroup-owner, but not
            # have testgroup we consider group are not managed by ldap
            # if g == groupname:
            #     is_group_exist = True
            # Or not
            is_group_exist = True

            level = self.get_ldap_group_access_level_by_name(g)

            # Find all members of this ldap group.
            members_search = self.ldap_obj.search_s(base=self.ldap_users_base_dn,
                                                    scope=ldap.SCOPE_SUBTREE,
                                                    filterstr=(
                                                        self.groups_memberof_filter % g),
                                                    attrlist=['sAMAccountName'])
            #  No members
            if len(members_search) == 0:
                continue

            for member in members_search:
                _, member_data = member
                if 'sAMAccountName' in member_data:
                    for x in member_data['sAMAccountName']:
                        uid = x.decode('utf-8')
                        if uid not in ldap_members:
                            ldap_members[uid] = {
                                'access_level': level
                            }
                        else:
                            if ldap_members[uid]['access_level'] < level:
                                ldap_members[uid]['access_level'] = level
        return ldap_members, is_group_exist

    def get_gitlab_group_members(self, group):
        """
        Return members of gitlab group
        """
        members = []
        for member in group.members.list(all=True):
            user = self.gl.users.get(member.id)
            members.append({
                'username': user.username,
                'object': member
            })
        return members

    def sync_groups(self, group, ldap_members):
        gitlab_group_members = self.get_gitlab_group_members(group)

        # pylint: disable=invalid-name
        for m in gitlab_group_members:
            # Check if member not in ldap group
            if m['username'] in ldap_members:
                continue
            user = self.get_gitlab_user_by_username(m['username'])
            # If user bot or not managed by current provider,
            # we cannot remove it
            if user.bot:
                logging.warning('User %s is bot', user.username)
                continue
            current_ldap_provider_user_dn = ''
            for i in user.identities:
                if i['provider'] == self.gitlab_ldap_provider:
                    current_ldap_provider_user_dn = i['extern_uid']
                    break
            if not current_ldap_provider_user_dn:
                logging.warning('Member %s is not managed by ldap %s',
                                user.username, self.gitlab_ldap_provider)
                continue
            self.remove_gitlab_group_member(group.name, m)

        root_member = next((
            item for item in gitlab_group_members if item["username"] == 'root'), None)
        root = self.get_gitlab_user_by_username('root')
        if not root_member:
            # Root user must be owner on all groups which synced
            self.create_gitlab_group_member(
                group, root, gitlab.const.OWNER_ACCESS)

        # If root has access level lesser than owner - fix it
        if root_member:
            self.fix_gitlab_group_member_access(group,
                                                root_member, gitlab.const.OWNER_ACCESS)

        for username, data in ldap_members.items():
            # If member exist in ldap group and not in gitlab - we need to add
            member = next((
                item for item in gitlab_group_members if item["username"] == username), None)
            if member is None:
                user = self.get_gitlab_user_by_username(username)
                # If user never login - he.s account are not created in gitlab
                # and we cannot add user to group, because we not create
                # accounts while sync
                if user is None:
                    logging.warning(
                        "User %s can.t be added to group %s because it not exist in gitlab. "
                        "User need to login before sync", username, group.name)
                    continue
                # If user is member and exist in gitlab - add as developer member
                self.create_gitlab_group_member(
                    group, user, data['access_level'])
            else:
                # logging.info(member["object"])
                # logging.info(member['object'].access_level)
                self.fix_gitlab_group_member_access(
                    group, member, data['access_level'])

    def sync_gitlab_groups(self):
        """
        Sync groups in gitlab.
        """
        logging.info('Sync groups')
        # gitlab_groups = {}
        for group in self.gl.groups.list(all=True):
            logging.info('Sync group %s', group.name)
            ldap_members, is_exist = self.get_ldap_gitlab_group_members(
                group.name, group_type="group")
            # Group is not managed by ldap
            if not is_exist:
                continue
            self.sync_groups(group=group,ldap_members=ldap_members)

    def sync_gitlab_subgroups(self):
        """
        Sync subgroups in gitlab.
        """
        logging.info('Sync subgroups')
        # gitlab_groups = {}
        for group in self.gl.groups.list(all=True):
            subgroups = group.subgroups.list()
            for subgroup_id in subgroups:
                real_group = self.gl.groups.get(subgroup_id.id)
                #logging.info(' subgroup rl %s', rl)
                ldap_members, is_exist = self.get_ldap_gitlab_group_members(
                    real_group.name, group_type="subgroup", mother_group=group.name)
                # Group is not managed by ldap
                if not is_exist:
                    continue

                self.sync_groups(group=real_group,ldap_members=ldap_members)
