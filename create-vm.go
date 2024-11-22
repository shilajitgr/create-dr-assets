package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

var secretData map[string]string

const (
	// secretData["resource_group_name"] = "vm_set"
	// vmName            = "goVM"
	// secretData["vnet_name"]          = vmName + "-vnet"
	// secretData["subnet_name"]        = vmName + "-subnet"
	nsgName = "network-nsg"
	// nicName           = vmName + "-nic"
	// diskName          = vmName + "-disk"
	// secretData["ip_name"]      = vmName + "-publicIP"
	// location          = "centralus"
	vaultURL = "https://rsc-config2.vault.azure.net/"
)

var (
	resourcesClientFactory *armresources.ClientFactory
	computeClientFactory   *armcompute.ClientFactory
	networkClientFactory   *armnetwork.ClientFactory
)

var (
	resourceGroupClient *armresources.ResourceGroupsClient

	virtualNetworksClient   *armnetwork.VirtualNetworksClient
	subnetsClient           *armnetwork.SubnetsClient
	securityGroupsClient    *armnetwork.SecurityGroupsClient
	publicIPAddressesClient *armnetwork.PublicIPAddressesClient
	interfacesClient        *armnetwork.InterfacesClient

	virtualMachinesClient *armcompute.VirtualMachinesClient
	disksClient           *armcompute.DisksClient
)

func main() {
	// Create a credential using the default Azure credentials
	conn, err := connectionAzure()
	if err != nil {
		log.Fatalf("cannot connect to Azure:%+v", err)
	}

	ctx := context.Background()

	client, err := azsecrets.NewClient(vaultURL, conn, nil)
	if err != nil {
		log.Fatalf("failed to create Key Vault client: %v", err)
	}

	secretName := "rsc-data2"

	// Retrieve the secret from Key Vault
	resp, err := client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		log.Printf("failed to retrieve secret: %v", err)
		fmt.Printf("Hey, sorry we couldn't load the secret value.\n")
		return
	}

	// Parse the secret value (assuming it's JSON formatted)
	secretValue := *resp.Value
	fmt.Printf("Retrieved secret value: %s\n", secretValue)

	// Example: Accessing a field like "vm_name" if the secret is in JSON format
	if err := json.Unmarshal([]byte(secretValue), &secretData); err != nil {
		log.Fatalf("failed to parse secret value as JSON: %v", err)
	}
	secretData["resource_group_name"] = "vm_set"
	// conn, err = rscMgmtConnectionAzure()
	conn, err = azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("cannot connect to Azure:%+v", err)
	}

	resourcesClientFactory, err = armresources.NewClientFactory(secretData["subscription_id"], conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	resourceGroupClient = resourcesClientFactory.NewResourceGroupsClient()

	networkClientFactory, err = armnetwork.NewClientFactory(secretData["subscription_id"], conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	virtualNetworksClient = networkClientFactory.NewVirtualNetworksClient()
	subnetsClient = networkClientFactory.NewSubnetsClient()
	securityGroupsClient = networkClientFactory.NewSecurityGroupsClient()
	publicIPAddressesClient = networkClientFactory.NewPublicIPAddressesClient()
	interfacesClient = networkClientFactory.NewInterfacesClient()

	computeClientFactory, err = armcompute.NewClientFactory(secretData["subscription_id"], conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	virtualMachinesClient = computeClientFactory.NewVirtualMachinesClient()
	disksClient = computeClientFactory.NewDisksClient()

	log.Println("start creating virtual machine...")
	// resourceGroup, err := createResourceGroup(ctx)
	// if err != nil {
	// 	log.Fatalf("cannot create resource group:%+v", err)
	// }
	// log.Printf("Created resource group: %s", *resourceGroup.ID)

	virtualNetwork, err := createVirtualNetwork(ctx)
	if err != nil {
		log.Fatalf("cannot create virtual network:%+v", err)
	}
	log.Printf("Created virtual network: %s", *virtualNetwork.ID)

	subnet, err := createSubnets(ctx)
	if err != nil {
		log.Fatalf("cannot create subnet:%+v", err)
	}
	log.Printf("Created subnet: %s", *subnet.ID)

	publicIP, err := createPublicIP(ctx)
	if err != nil {
		log.Fatalf("cannot create public IP address:%+v", err)
	}
	log.Printf("Created public IP address: %s", *publicIP.ID)

	// network security group
	nsg, err := createNetworkSecurityGroup(ctx)
	if err != nil {
		log.Fatalf("cannot create network security group:%+v", err)
	}
	log.Printf("Created network security group: %s", *nsg.ID)

	netWorkInterface, err := createNetWorkInterface(ctx, *subnet.ID, *publicIP.ID, *nsg.ID)
	if err != nil {
		log.Fatalf("cannot create network interface:%+v", err)
	}
	log.Printf("Created network interface: %s", *netWorkInterface.ID)

	networkInterfaceID := netWorkInterface.ID
	virtualMachine, err := createVirtualMachine(ctx, *networkInterfaceID)
	if err != nil {
		log.Fatalf("cannot create virual machine:%+v", err)
	}
	log.Printf("Created network virual machine: %s", *virtualMachine.ID)

	log.Println("Virtual machine created successfully")
}

func rscMgmtConnectionAzure() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewClientSecretCredential(secretData["tenant_id"], secretData["client_id"], secretData["client_secret"], nil)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func connectionAzure() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func createResourceGroup(ctx context.Context) (*armresources.ResourceGroup, error) {

	parameters := armresources.ResourceGroup{
		Location: to.Ptr(secretData["location"]),
		Tags:     map[string]*string{"sample-rs-tag": to.Ptr("sample-tag")}, // resource group update tags
	}

	resp, err := resourceGroupClient.CreateOrUpdate(ctx, secretData["resource_group_name"], parameters, nil)
	if err != nil {
		return nil, err
	}

	return &resp.ResourceGroup, nil
}

func createVirtualNetwork(ctx context.Context) (*armnetwork.VirtualNetwork, error) {

	parameters := armnetwork.VirtualNetwork{
		Location: to.Ptr(secretData["location"]),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{
					to.Ptr("10.1.0.0/16"), // example 10.1.0.0/16
				},
			},
			//Subnets: []*armnetwork.Subnet{
			//	{
			//		Name: to.Ptr(secretData["subnet_name"]+"3"),
			//		Properties: &armnetwork.SubnetPropertiesFormat{
			//			AddressPrefix: to.Ptr("10.1.0.0/24"),
			//		},
			//	},
			//},
		},
	}

	pollerResponse, err := virtualNetworksClient.BeginCreateOrUpdate(ctx, secretData["resource_group_name"], secretData["vnet_name"], parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.VirtualNetwork, nil
}

func createSubnets(ctx context.Context) (*armnetwork.Subnet, error) {

	parameters := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.Ptr("10.1.10.0/24"),
		},
	}

	pollerResponse, err := subnetsClient.BeginCreateOrUpdate(ctx, secretData["resource_group_name"], secretData["vnet_name"], secretData["subnet_name"], parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Subnet, nil
}

func createPublicIP(ctx context.Context) (*armnetwork.PublicIPAddress, error) {

	parameters := armnetwork.PublicIPAddress{
		Location: to.Ptr(secretData["location"]),
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic), // Static or Dynamic
		},
	}

	pollerResponse, err := publicIPAddressesClient.BeginCreateOrUpdate(ctx, secretData["resource_group_name"], secretData["ip_name"], parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PublicIPAddress, err
}

func createNetworkSecurityGroup(ctx context.Context) (*armnetwork.SecurityGroup, error) {

	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(secretData["location"]),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				// Windows connection to virtual machine needs to open port 3389,RDP
				// inbound
				{
					Name: to.Ptr("sample_inbound_22"), //
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),
						SourcePortRange:          to.Ptr("*"),
						DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),
						DestinationPortRange:     to.Ptr("22"),
						Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolTCP),
						Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
						Priority:                 to.Ptr[int32](100),
						Description:              to.Ptr("sample network security group inbound port 22"),
						Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
					},
				},
				// outbound
				{
					Name: to.Ptr("sample_outbound_22"), //
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),
						SourcePortRange:          to.Ptr("*"),
						DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),
						DestinationPortRange:     to.Ptr("22"),
						Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolTCP),
						Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
						Priority:                 to.Ptr[int32](100),
						Description:              to.Ptr("sample network security group outbound port 22"),
						Direction:                to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
					},
				},
			},
		},
	}

	pollerResponse, err := securityGroupsClient.BeginCreateOrUpdate(ctx, secretData["resource_group_name"], nsgName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.SecurityGroup, nil
}

func createNetWorkInterface(ctx context.Context, subnetID string, publicIPID string, networkSecurityGroupID string) (*armnetwork.Interface, error) {

	parameters := armnetwork.Interface{
		Location: to.Ptr(secretData["location"]),
		Properties: &armnetwork.InterfacePropertiesFormat{
			//NetworkSecurityGroup:
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("ipConfig"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
						Subnet: &armnetwork.Subnet{
							ID: to.Ptr(subnetID),
						},
						PublicIPAddress: &armnetwork.PublicIPAddress{
							ID: to.Ptr(publicIPID),
						},
					},
				},
			},
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: to.Ptr(networkSecurityGroupID),
			},
		},
	}

	pollerResponse, err := interfacesClient.BeginCreateOrUpdate(ctx, secretData["resource_group_name"], secretData["nic_name"], parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Interface, err
}

func createVirtualMachine(ctx context.Context, networkInterfaceID string) (*armcompute.VirtualMachine, error) {
	//require ssh key for authentication on linux
	//sshPublicKeyPath := "/home/user/.ssh/id_rsa.pub"
	//var sshBytes []byte
	//_,err := os.Stat(sshPublicKeyPath)
	//if err == nil {
	//	sshBytes,err = ioutil.ReadFile(sshPublicKeyPath)
	//	if err != nil {
	//		return nil, err
	//	}
	//}

	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(secretData["location"]),
		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					// search image reference
					// az vm image list --output table
					ID: to.Ptr("/subscriptions/02f031f1-f05f-4709-8cf7-68d2e343065d/resourceGroups/vm_set/providers/Microsoft.Compute/galleries/Source/images/Base/versions/1.0.0"),
					//require ssh key for authentication on linux
					//Offer:     to.Ptr("UbuntuServer"),
					//Publisher: to.Ptr("Canonical"),
					//SKU:       to.Ptr("18.04-LTS"),
					//Version:   to.Ptr("latest"),
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_B2s")), // VM size include vCPUs,RAM,Data Disks,Temp storage.
			},
			OSProfile: &armcompute.OSProfile{ //
				ComputerName:  to.Ptr("sample-compute"),
				AdminUsername: to.Ptr("sample-user"),
				AdminPassword: to.Ptr("Password01!@#"),
				//require ssh key for authentication on linux
				//LinuxConfiguration: &armcompute.LinuxConfiguration{
				//	DisablePasswordAuthentication: to.Ptr(true),
				//	SSH: &armcompute.SSHConfiguration{
				//		PublicKeys: []*armcompute.SSHPublicKey{
				//			{
				//				Path:    to.Ptr(fmt.Sprintf("/home/%s/.ssh/authorized_keys", "sample-user")),
				//				KeyData: to.Ptr(string(sshBytes)),
				//			},
				//		},
				//	},
				//},
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: to.Ptr(networkInterfaceID),
					},
				},
			},
		},
	}

	pollerResponse, err := virtualMachinesClient.BeginCreateOrUpdate(ctx, secretData["resource_group_name"], secretData["vm_name"], parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.VirtualMachine, nil
}
