# Gitlab sync with ldap

- Work only with LDAP AD, but can be adapted by using attributes of necessary LDAP Provider (example FreeIPA)

## Sync

- Users
  - They are not created automatically
  - The user name is synchronized (From the DisplayName property)
  - The administrator status is synchronized (Based on group membership)
  - They are blocked (*ban) if they are excluded from the LDAP_GITLAB_USERS_GROUP group or have a password that expired more than 2 days ago. Unlock if the membership condition is met and the password has not expired.
  - SSH keys are synchronized (From the ipaSshPubKey property, synchronized keys have the prefix 'FreeIPA managed key')
  - Deleted if the account is missing in ldap
- Groups
  - Automatic create group from LDAP AD if it not exists in GitLab
  - Automatic create subgroup in group from LDAP AD if it not exists in GitLab
  - Sync role depends on group naming. If ACCESS_LEVEL is not specified using default role - Developer


  
  GROUP NAME TEMLATE
  ```text
  {LDAP_GITLAB_GROUP_PREFIX}-{GROUPNAME}-{ACCESS_LEVEL}
  ```

  ***gitlab-group-test-owner*** - role ***owner*** in group ***test***

  SUBGROUP NAME TEMLATE
  ```text
  {LDAP_GITLAB_SUBGROUP_PREFIX}-{GROUPNAME}-{SUBGROUPNAME}-{ACCESS_LEVEL}
  ```
  ***gitlab-subgroup-test-subtest-owner*** - role ***owner*** in subgroup ***subtest*** in group ***test***

## Config

Configuration via environment variables

- SYNC_DRY_RUN: Running in dry-run mode. The changes are not applied
- GITLAB_API_URL: Url for accessing Gitlab (Approx. - <https://gitlab.example.com >)
- GITLAB_TOKEN: Token for working with the Gitlab API
- GITLAB_LDAP_PROVIDER: The provider name specified in the ldap configuration for Gitlab
- LDAP_URL: URL for FreeIPA (Approx. - ldap://ipa.example.com)
- LDAP_USERS_BASE_DN: Base DN for users
- LDAP_GROUP_BASE_DN: Base DN for groups
- LDAP_BIND_DN: Bind DN in LDAP
- LDAP_PASSWORD: Password in LDAP
- LDAP_GITLAB_USERS_GROUP: The group that is allowed to enter the gitlab. Accounts are synchronized based on this group. Accounts that are not part of this group are set to the banned state. The default value is ***gitlab-users***
- LDAP_GITLAB_ADMIN_GROUP: A group whose users have administrator rights in Gitlab. The default value is ***gitlab-admins***
- LDAP_GITLAB_GROUP_PREFIX: The prefix of LDAP groups for synchronizing members of Gitlab groups. Groups must exist in Gitlab. The default value is ***gitlab-group-***
- LDAP_GITLAB_SUBGROUP_PREFIX: Prefix LDAP-subgroup for sync group membership.