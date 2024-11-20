package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

type VMConfig struct {
	SubscriptionID    string `json:"subscription_id"`
	ResourceGroupName string `json:"resource_group_name"`
	Location          string `json:"location"`
	VNetName          string `json:"vnet_name"`
	SubnetName        string `json:"subnet_name"`
	IPName            string `json:"ip_name"`
	IPConfigName      string `json:"ip_config_name"`
	NICName           string `json:"nic_name"`
	VMName            string `json:"vm_name"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	TenantID          string `json:"tenant_id"`
}

func main() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}

	vmConfig, err := getVMConfigFromKeyVault(cred, "https://your-keyvault-name.vault.azure.net/", "vm-config-secret")
	if err != nil {
		log.Fatalf("failed to get VM config from Key Vault: %v", err)
	}

	// Initialize resource clients
	resourceGroupClient := armresources.NewResourceGroupsClient(vmConfig.SubscriptionID, cred, nil)
	vnetClient := armnetwork.NewVirtualNetworksClient(vmConfig.SubscriptionID, cred, nil)
	subnetClient := armnetwork.NewSubnetsClient(vmConfig.SubscriptionID, cred, nil)
	ipClient := armnetwork.NewPublicIPAddressesClient(vmConfig.SubscriptionID, cred, nil)
	nicClient := armnetwork.NewNetworkInterfacesClient(vmConfig.SubscriptionID, cred, nil)
	vmClient := armcompute.NewVirtualMachinesClient(vmConfig.SubscriptionID, cred, nil)

	// Create resource group
	_, err = resourceGroupClient.CreateOrUpdate(context.TODO(), vmConfig.ResourceGroupName, armresources.ResourceGroup{
		Location: &vmConfig.Location,
	})
	if err != nil {
		log.Fatalf("failed to create resource group: %v", err)
	}
	fmt.Println("Resource group created")

	// Create virtual network
	_, err = vnetClient.BeginCreateOrUpdate(context.TODO(), vmConfig.ResourceGroupName, vmConfig.VNetName, armnetwork.VirtualNetwork{
		Location: &vmConfig.Location,
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")},
			},
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to create virtual network: %v", err)
	}
	fmt.Println("Virtual network created")

	// Create subnet
	_, err = subnetClient.BeginCreateOrUpdate(context.TODO(), vmConfig.ResourceGroupName, vmConfig.VNetName, vmConfig.SubnetName, armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.Ptr("10.0.0.0/24"),
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to create subnet: %v", err)
	}
	fmt.Println("Subnet created")

	// Create public IP
	_, err = ipClient.BeginCreateOrUpdate(context.TODO(), vmConfig.ResourceGroupName, vmConfig.IPName, armnetwork.PublicIPAddress{
		Location: &vmConfig.Location,
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to create public IP: %v", err)
	}
	fmt.Println("Public IP created")

	// Create network interface
	_, err = nicClient.BeginCreateOrUpdate(context.TODO(), vmConfig.ResourceGroupName, vmConfig.NICName, armnetwork.NetworkInterface{
		Location: &vmConfig.Location,
		Properties: &armnetwork.NetworkInterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.NetworkInterfaceIPConfiguration{
				{
					Name: &vmConfig.IPConfigName,
					Properties: &armnetwork.NetworkInterfaceIPConfigurationPropertiesFormat{
						Subnet: &armnetwork.Subnet{
							ID: to.Ptr("/subscriptions/" + vmConfig.SubscriptionID + "/resourceGroups/" + vmConfig.ResourceGroupName + "/providers/Microsoft.Network/virtualNetworks/" + vmConfig.VNetName + "/subnets/" + vmConfig.SubnetName),
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to create network interface: %v", err)
	}
	fmt.Println("Network interface created")

	// Create virtual machine
	_, err = vmClient.BeginCreateOrUpdate(context.TODO(), vmConfig.ResourceGroupName, vmConfig.VMName, armcompute.VirtualMachine{
		Location: &vmConfig.Location,
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypesStandardDS1V2),
			},
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					Publisher: to.Ptr("Canonical"),
					Offer:     to.Ptr("UbuntuServer"),
					SKU:       to.Ptr("18.04-LTS"),
					Version:   to.Ptr("latest"),
				},
			OSProfile: &armcompute.OSProfile{
				ComputerName:  &vmConfig.VMName,
				AdminUsername: &vmConfig.Username,
				AdminPassword: &vmConfig.Password,
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: to.Ptr("/subscriptions/" + vmConfig.SubscriptionID + "/resourceGroups/" + vmConfig.ResourceGroupName + "/providers/Microsoft.Network/networkInterfaces/" + vmConfig.NICName),
					},
				},
			},
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to create virtual machine: %v", err)
	}
	fmt.Println("Virtual machine created")
}

func getVMConfigFromKeyVault(cred *azidentity.DefaultAzureCredential, keyVaultURL, secretName string) (*VMConfig, error) {
	client := azsecrets.NewClient(keyVaultURL, cred, nil)

	secretResp, err := client.GetSecret(context.TODO(), secretName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %v", err)
	}

	var config VMConfig
	err = json.Unmarshal([]byte(*secretResp.Value), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	return &config, nil
}

func to[T any](v T) *T {
	return &v
}
