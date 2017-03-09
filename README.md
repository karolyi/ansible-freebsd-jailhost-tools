Role Name
=========

This role is a set of tools for maintaining FreeBSD jails using ZFS. The nature of this role is to include the `tasks/jail/main.yml` with the proper variables set up. It will check if the underlying OS version in the jail is outdated, and update if necessary, while calling configured hooks during the process.

I use this on my single server box to maintain separation between various services. Of course, the nature of Ansible does make this rule and anything that uses it, scalable.

Requirements
------------

A fairly recent FreeBSD box.

Role Variables
--------------

Variables this role uses are defined in the `defaults/main.yml` file, using sensible defaults. Override then at your convenience.

Dependencies
------------

This role depends on an already existing 'jail template', that is provided by the role `karolyi.freebsd-zfs-jailtemplate`.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts:
        - localhost
      roles:
         - karolyi.ansible-freebsd-jailhost-tools

License
-------

BSD

Author Information
------------------

László Károlyi: [Linkedin profile](https://linkedin.com/in/karolyi)

