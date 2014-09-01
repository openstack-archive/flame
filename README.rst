Flame: Automatic Heat template generation
============================================

Description
-----------

Heat
^^^^

OpenStack Orchestration project Heat implements an orchestration engine to
launch multiple composite cloud applications based on templates. A Heat
template describes infrastructure resources (servers, networks, floating ips,
etc) and the relationships between these resources, allowing Heat to deploy the
resources in a correct order and to manage whole infrastructure lifecycle.

Today Heat provides compatibility with the AWS CloudFormation template format
and has its own, native format called Heat Orchestration Template (HOT).


Flame
^^^^^

In this blog-post I will talk about Flame, a tool that generates HOT Heat
template from already existing infrastructure. Currently this project is
developed by Thomas Herve (Heat core developer) and myself and provides support
for Nova (key pairs and servers), Cinder (volumes) and Neutron (router,
networks, subnets, security groups and floating IPs) resources.

Flame works as follows: using provided credentials (user name, project name,
password, authentication url), the tool will list supported resources deployed
in the project and will generate corresponding, highly customized HOT template.


First example : Router, network, instance from image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The easiest way to understand how Flame works is to show some examples. So here
they are.

Suppose that in your project you deployed a router, a network with
corresponding subnet and an instance that is booted from an image. A public key
was imported in the project and used to access the instance, a floating IP was
associated with the instance and the default security group was modified in
order to allow incoming ssh connection.

For this infrastructure, Flame will generate a template that will look like this::

    description: Generated template
    heat_template_version: 2013-05-23
    parameters:
      external_network_for_floating_ip_0:
        constraints:
        - custom_constraint: neutron.network
        description: Network to allocate floating IP from
        type: string
      flavor_server_0:
        default: m1.small
        description: Flavor to use for instance my_instance
        type: string
      image_server_0:
        description: Image to use to boot instance my_instance
        type: string
      router_0_external_network:
        constraints:
        - custom_constraint: neutron.network
        description: Router external network
        type: string
    resources:
      floatingip_0:
        properties:
          floating_network_id:
            get_param: external_network_for_floating_ip_0
        type: OS::Neutron::FloatingIP
      key_0:
        properties:
          name: arezmerita
          public_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8u8FIZjmhO+hM/f+2J9qYKgJPG16pQmBfQeUvFlC5u9xxf57eGKuq7xYMIoW63gGM8dnsXcQp9Lmp/+TacwPkis5Q8LKriJSxZUgwczM2ppwwJ/SOraRDHy+2bgbrrO2ZYNdoD5zBaiC5jh6YemrB+y5TtkiEo+llNZw+6e5TlZxEEGD4Zgid/Tfz4qwkKvoGwx34ltQ+XvT2Tv6kE7JWc8rR37wkCbLVQd3G3vAJFI3bWrYan3XNP5+wsVydWn3APF2l8FtLkSpE5Fkai7OWACPRZ9zNlQSBk6pRNlxfZ8jQL6Kuk3MU2tTrqw5g/jG7Hlu3vCeDIYOiFI2a8GUX
        type: OS::Nova::KeyPair
      network_0:
        properties:
          admin_state_up: true
          name: network
          shared: false
        type: OS::Neutron::Net
      network_subnet_0:
        properties:
          allocation_pools:
          - end: 10.0.48.254
            start: 10.0.48.242
          cidr: 10.0.48.240/28
          dns_nameservers: []
          enable_dhcp: true
          host_routes: []
          ip_version: 4
          name: network_subnet
          network_id:
            get_resource: network_0
        type: OS::Neutron::Subnet
      newdefault_0:
        properties:
          description: default
          name: newdefault
          rules:
          - direction: egress
            ethertype: IPv6
          - direction: ingress
            ethertype: IPv6
            remote_mode: remote_group_id
          - direction: ingress
            ethertype: IPv4
            port_range_max: 22
            port_range_min: 22
            protocol: tcp
            remote_ip_prefix: 0.0.0.0/0
          - direction: egress
            ethertype: IPv4
          - direction: ingress
            ethertype: IPv4
            remote_mode: remote_group_id
        type: OS::Neutron::SecurityGroup
      router_0:
        properties:
          admin_state_up: true
          name: router
        type: OS::Neutron::Router
      router_0_gateway:
        properties:
          network_id:
            get_param: router_0_external_network
          router_id:
            get_resource: router_0
        type: OS::Neutron::RouterGateway
      router_0_interface_0:
        properties:
          router_id:
            get_resource: router_0
          subnet_id:
            get_resource: network_subnet_0
        type: OS::Neutron::RouterInterface
      server_0:
        properties:
          block_device_mapping: []
          config_drive: ''
          diskConfig: AUTO
          flavor:
            get_param: flavor_server_0
          image:
            get_param: image_server_0
          key_name:
            get_resource: key_0
          name: my_instance
          networks:
          - network:
              get_resource: network_0
          security_groups:
          - get_resource: newdefault_0
        type: OS::Nova::Server

It’s not so easy to write a template like this manually, right?

There are two major sections in this generated template: parameters and
resources. The parameters section is used to customize each deployment, by
specifying input parameters for template instantiation. In the resources
section, are defined actual resources that will compose a Heat stack deployed
from the HOT template.

In order to understand this generated template and to be able to modify it, I
will explain here for each resource type, the possible parameters and its
relationship with other resources.

Floating IP
"""""""""""
::
      floatingip_0:
        properties:
          floating_network_id:
            get_param: external_network_for_floating_ip_0
        type: OS::Neutron::FloatingIP

Each resource declaration block is headed by the resource ID: floatingip_0 for
this resource. Every resource ID must be unique within the resource
section. Type attribute specifies the type of resource: OS::Neutron::FloatingIP
in this case.

Since a floating IP is allocated from a network, we must indicate the
network id. To be fully customisable, instead of hard coding a network id, we
add a parameter external_network_for_floating_ip_0, that will be provided by
the user during Heat stack creation.

Key Pair used to access the instance
""""""""""""""""""""""""""""""""""""
::
      key_0:
        properties:
          name: arezmerita
          public_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8u8FIZjmhO+hM/f+2J9qYKgJPG16pQmBfQeUvFlC5u9xxf57eGKuq7xYMIoW63gGM8dnsXcQp9Lmp/+TacwPkis5Q8LKriJSxZUgwczM2ppwwJ/SOraRDHy+2bgbrrO2ZYNdoD5zBaiC5jh6YemrB+y5TtkiEo+llNZw+6e5TlZxEEGD4Zgid/Tfz4qwkKvoGwx34ltQ+XvT2Tv6kE7JWc8rR37wkCbLVQd3G3vAJFI3bWrYan3XNP5+wsVydWn3APF2l8FtLkSpE5Fkai7OWACPRZ9zNlQSBk6pRNlxfZ8jQL6Kuk3MU2tTrqw5g/jG7Hlu3vCeDIYOiFI2a8GUX
        type: OS::Nova::KeyPair

Like floating IP resource, this key pair resource has an ID and a type. In
addition, the name and the value of the public key are specified.

Network
"""""""
::
      network_0:
        properties:
          admin_state_up: true
          name: network
          shared: false
        type: OS::Neutron::Net
      network_subnet_0:
        properties:
          allocation_pools:
          - end: 10.0.48.254
            start: 10.0.48.242
          cidr: 10.0.48.240/28
          dns_nameservers: []
          enable_dhcp: true
          host_routes: []
          ip_version: 4
          name: network_subnet
          network_id:
            get_resource: network_0
        type: OS::Neutron::Subnet

Declaration of the network resource does not differ much from from two previous
resources. However, the subnet resource that belongs to the network_0 resource
requires its network ID. Since we do not know it, we will just reference
network_0 resource using get_resource: network_0. At runtime, this reference
will be resolved to reference ID of the network resource.

Router, router gateway, router interface
""""""""""""""""""""""""""""""""""""""""
::
      router_0:
        properties:
          admin_state_up: true
          name: router
        type: OS::Neutron::Router
      router_0_gateway:
        properties:
          network_id:
            get_param: router_0_external_network
          router_id:
            get_resource: router_0
        type: OS::Neutron::RouterGateway
      router_0_interface_0:
        properties:
          router_id:
            get_resource: router_0
          subnet_id:
            get_resource: network_subnet_0
        type: OS::Neutron::RouterInterface

These three resources are closely related. The router_0 resource declares a
router. The router_0_gateway declares external network gateway for this router
and expects a parameter from the user ( get_param: router_0_external_network ),
that corresponds to the ID of the external network for the gateway.

The router_0_interface_0 resource declares an internal network interface to the
router_0.

Security group
""""""""""""""
::
      newdefault_0:
        properties:
          description: default
          name: newdefault
          rules:
          - direction: egress
            ethertype: IPv6
          - direction: ingress
            ethertype: IPv6
            remote_mode: remote_group_id
          - direction: ingress
            ethertype: IPv4
            port_range_max: 22
            port_range_min: 22
            protocol: tcp
            remote_ip_prefix: 0.0.0.0/0
          - direction: egress
            ethertype: IPv4
          - direction: ingress
            ethertype: IPv4
            remote_mode: remote_group_id
        type: OS::Neutron::SecurityGroup

The default security group is created automatically for each project. The user
can add new rules in this group, but the user is not allowed to delete this
group or create another security group with the name default. For this reason,
when we export this group, we rename it to _default.

Instance
""""""""
::
      server_0:
        properties:
          block_device_mapping: []
          config_drive: ''
          diskConfig: AUTO
          flavor:
            get_param: flavor_server_0
          image:
            get_param: image_server_0
          key_name:
            get_resource: key_0
          name: my_instance
          networks:
          - network:
              get_resource: network_0
          security_groups:
          - get_resource: newdefault_0
        type: OS::Nova::Server

The last resource corresponds to the instance. The flavor and image used to
boot this server must be specified by the user : get_param: flavor_server_0 and
get_param: image_server_0. The keypair name, network and security group will be
automatically resolved.

Second example : Router, network, two instances, volumes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The second example will focus on volumes. Like in previous example, in your
project you deployed a router, a network with corresponding subnet and two
instances. The first instance was booted from a volume that was created from an
image. The second instance was booted from an image and a volume is attached to
this instance.

For this infrastructure, generated template will look like this (only the major
differences are showed):

::
    description: Generated template
    heat_template_version: 2013-05-23
    parameters:
    ......
      flavor_server_0:
        default: m1.small
        description: Flavor to use for instance instance
        type: string
      flavor_server_1:
        default: m1.small
        description: Flavor to use for instance instance_from_volume
        type: string
      image_server_0:
        description: Image to use to boot instance instance
        type: string
      volume_image_1:
        description: Image to create volume volume_from_image
        type: string
      volume_type_0:
        default: iscsi
        description: Volume type for volume resource volume_0
        type: string
      volume_type_1:
        default: iscsi
        description: Volume type for volume resource volume_1
        type: string
    resources:
    ......
      server_0:
        properties:
          block_device_mapping:
          - device_name: /dev/vdb
            volume_id:
              get_resource: volume_0
          diskConfig: AUTO
          flavor:
            get_param: flavor_server_0
          image:
            get_param: image_server_0
          key_name:
            get_resource: key_0
          name: instance
          networks:
          - network:
              get_resource: network_0
          security_groups:
          - get_resource: _default_0
        type: OS::Nova::Server
      server_1:
        properties:
          block_device_mapping:
          - device_name: vda
            volume_id:
              get_resource: volume_1
          diskConfig: AUTO
          flavor:
            get_param: flavor_server_1
          key_name:
            get_resource: key_0
          name: instance_from_volume
          networks:
          - network:
              get_resource: network_0
          security_groups:
          - get_resource: _default_0
        type: OS::Nova::Server
      volume_0:
        properties:
          metadata:
            attached_mode: rw
            readonly: 'False'
          name: volume
          size: 10
          volume_type:
            get_param: volume_type_0
        type: OS::Cinder::Volume
      volume_1:
        properties:
          image:
            get_param: volume_image_1
          metadata:
            attached_mode: rw
            readonly: 'False'
          name: volume_from_image
          size: 10
          volume_type:
            get_param: volume_type_1
        type: OS::Cinder::Volume

As in the previous example, each resource is identified by an ID. Since in this
example we have two volumes and two instances, two **OS::Cinder::Volume** and
two **OS::Nova::Server** resources are added.

In this example, for two server resources, the properties section
**block_device_mapping** is used to express the fact that

- the volume resource **volume_0** is attached to **server_0** on **/dev/vdb**
- that volume resource **volume_1** is used as boot source for **server_1** on
  **vda** device.

And since an image is used to create bootable volume **volume_1**, Flame will
add **volume_image_1** parameter in template parameters section.

Conclusion
^^^^^^^^^^

In this article we saw how to use Flame to automatically generate Heat template
from existing infrastructure. Generated template is highly customized, can be
easily modified and reused on every OpenStack installation (with Heat of
cause).

Since Flame is still in development, there are some interesting features that
we will add to improve it: enrich the set of supported resources, add stack
data file generation, that will help users to “adopt” Heat stacks from already
existing resources, and the last, but not the least, we would like to improve
resource selection i.e. give the user the possibility to specify one by one
what resource he/she wants to export in template.
