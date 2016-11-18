# CloudStack Container Service

## Introduction

The CloudStack Container Service (CCS) orchestrates provisioning of [Kubernetes](http://kubernetes.io) managed container clusters in a virtual machines and networks managed by [Apache CloudStack](http://cloudstack.apache.org).  CCS builds container clusters Kubernetes running on [CoreOS](https://coreos.com/why/) (Alpha Channel) VMs. Once provisioned, users are able to configure the cluster and deploy containers using standard Kubernetes tools such as kubectl.  Currently, CCS provides the following features for managing container clusters:

  * Orchestrates provisioning of Kubernetes 1.2.4 container clusters using KVM, VMware, or XenServer hosted virtual machines using the CloudStack Admin Console or API 

  * Embeds the [Kubernetes Dashboard](http://kubernetes.io/docs/user-guide/ui/) in the CloudStack Admin Console to deploy containerized applications

  * Integrates the Kubernetes cluster lifecycle with the CloudStack event log

  * Injects CloudStack managed SSH keys into Kubernetes clusters

  * Monitors Kubernetes cluster health 

  * Connect Kubernetes clusters to CloudStack isolated networks with integrated DNS (using [SkyDNS](https://github.com/skynetservices/skydns))

  * Use private docker repositories as a source for container images

  * Support for CoreOS guests

## Installation

CCS is implemented as a CloudStack management server plugin. Therefore, a functioning CloudStack management server is prequisite for installation. CCS is distributed as DEB/RPM packages installed from public Yum/Apt repositories.  The packages include a script to download and install the default CoreOS template into each zone. Following installation of the default CoreOS template, CCS will be ready for use.

For more detailed installation instructions and supported CloudStack releases and hypervisors, please see the [CCS Installation and Administation Guide](https://downloads.shapeblue.com/ccs/1.0/Installation_and_Administration_Guide.pdf)

## Development

The CCS plugin source is managed separately from the main CloudStack repository.  As a plugin, it depends on modules from the CloudStack management server.  By linking this repository to a CloudStack repository as a [subtree](https://git-scm.com/book/en/v1/Git-Tools-Subtree-Merging), this project can version match its dependencies and deploy into a full CloudStack build.  The following steps will establish the linkage between this repository and a CloudStack repository:

  1. Add a remote for this repository to your CloudStack repository: `git remote add -f ccs <ccs repository fork>`
  2. From the root of your CloudStack repository, add a subtree reference to the `plugins` directory: `git subtree add -P plugins/ccs ccs master`

With this subtree reference, make suitable changes and commit as you would normally do in the `plugins/ccs` directory.  Ammend a `-P` option to the `git add` and `git commit` commands when interacting with the subtree

    git add -P
    git commit -s

To push changes to ccs repository, push your development branch with the following command:

    `git subtree push -P plugins/ccs ccs new-shiny-branch`

After the PR is accepted, you can pull changes:

   `git subtree pull -P plugins/ccs sbccs master`

