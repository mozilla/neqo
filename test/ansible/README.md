# Ansible playbooks for our self-hosted CI runners

This directory contains Ansible playbooks used for configuring and managing our self-hosted CI runners. Check [`inventory.ini`](inventory.ini) for the current runners.

## Ansible setup

In order to minimize the number of command-line arguments needed to pass to Ansible, set these environment variables before running the playbooks:

```bash
export ANSIBLE_REMOTE_USER=${YOUR_USERNAME_ON_THE_RUNNERS}
export ANSIBLE_INVENTORY=inventory.ini
export ANSIBLE_STRATEGY=free
```

## Bringing up a new runner

To bring up a new runner, you need to `ssh` into the SRE-provisioned machine and upgrade it to the latest LTS version of Ubuntu first. You can do that by repeatedly running:

```bash
sudo do-release-upgrade
sudo reboot
```

Repeat the process until no more Ubuntu upgrades are available. Then add the DNS name of the runner to [`inventory.ini`](inventory.ini) in the `[moonshots]` group.

Next, make sure you have a GitHub Personal Access Token (PAT) in the `GITHUB_API_TOKEN` environment variable:

```bash
export GITHUB_API_TOKEN=${YOUR_PERSONAL_ACCESS_TOKEN}
```

Now, make sure all runners, including the new one, are reachable by running:

```bash
ansible all -m ping
```

If successful, run the `shrink.yml` playbook to remove unnecessary packages:

```bash
ansible-playbook shrink.yml
```

Then install the runner software and all required dependencies by running:

```bash
ansible-playbook install.yml
```
