"""A Pulumi Dynamic Provider to utilize the Azure SDK to create Access Policies and SAS tokens from them"""

from typing import Optional
from dataclasses import dataclass
from pulumi import Input, ResourceOptions, Output
from pulumi.dynamic import ResourceProvider, CheckResult, CheckFailure, CreateResult, DiffResult, UpdateResult, Resource
from pulumi_azure_native.storage import list_storage_account_keys_output
from azure.storage.blob import BlobServiceClient, AccessPolicy, ContainerSasPermissions, ContainerClient, generate_container_sas


@dataclass
class ContainerAccessPolicyArgs:
    """Arguments which will be passed to the ContainerAccessPolicyProvider"""
    storage_account: Input[str]
    resource_group: Input[str]
    container_name: Input[str]
    policies: Input[dict]


class ContainerAccessPolicyProvider(ResourceProvider):
    """A Dynamic Provider as documented at https://www.pulumi.com/docs/intro/concepts/resources/dynamic-providers/
    Specifically it uses the Azure SDK as documented at https://docs.microsoft.com/en-us/python/api/overview/azure/storage-blob-readme
    """
    read_access_policy = AccessPolicy(permission=ContainerSasPermissions(read=True, list=True),
                                      expiry="2100-01-01T00:00:00.0000000Z",
                                      start="2022-01-01T00:00:00.0000000Z")
    write_access_policy = AccessPolicy(permission=ContainerSasPermissions(read=True, write=True, delete=True, list=True, add=True, create=True),
                                       expiry="2100-01-01T00:00:00.0000000Z",
                                       start="2022-01-01T00:00:00.0000000Z")

    def check(self, _olds: dict, news: dict) -> CheckResult:
        failures = []
        if not isinstance(news.get("container_name"), str):
            failures.append(CheckFailure("container_name", "Must be a string"))
        policies = news.get("policies")
        if not isinstance(policies, dict):
            failures.append(CheckFailure("policies", "Must be a dictionary[name, permission]"))
            return CheckResult(inputs={}, failures=failures)
        if len(policies) > 5 or len(policies) < 1:
            failures.append(CheckFailure("policies", "dictionary must contain between 1 and 5 entries"))
        lowered_policies = {}
        for name, permission in policies.items():
            if len(name) > 64 or len(name) < 1:
                failures.append(CheckFailure("policies", "name must be between 1 and 64 characters in length"))
            if not isinstance(permission, str) or permission.lower() not in ["read", "write"]:
                failures.append(CheckFailure("policies", "dictionary value for permission must be 'read' or 'write'"))
            lowered_policies[name] = permission.lower()
        news["policies"] = lowered_policies
        return CheckResult(inputs=news, failures=failures)

    def create(self, props: dict) -> CreateResult:
        container_name = props["container_name"]
        identifiers = {}
        policies = props["policies"]
        for name, permission in policies.items():
            identifiers[name] = (self.read_access_policy if permission == "read" else self.write_access_policy)
        container_client = self.get_container_client(props["connection_string"], container_name)
        self.set_access_policy(container_client, "creating", container_name, identifiers)
        props["tokens"] = self.generate_tokens(policies, container_client)
        return CreateResult(id_=container_name, outs=props)

    def diff(self, _id: str, _olds: dict, _news: dict) -> DiffResult:
        # We are not going to rely on _olds.  Will make a call to get the current values to revert potential click-ops.
        # Inspiration from https://bit.ly/3MXSORo
        # Only replace if the storage account or container name changes. Otherwise just update,
        replaces = []
        if _olds["storage_account"] != _news["storage_account"]:
            replaces.append("storage_account")
        if _olds["container_name"] != _news["container_name"]:
            replaces.append("container_name")
        change = bool(len(replaces) != 0)

        if not change:
            try:
                service_client = BlobServiceClient.from_connection_string(_news["connection_string"])
                container_client = service_client.get_container_client(_id)
                azure_policy = container_client.get_container_access_policy()
            except Exception as error:
                raise Exception(f"Error getting existing Access Policy for {_id}.\nError: {error}") from error
            new_policies = _news["policies"]
            azure_policies = azure_policy["signed_identifiers"]
            if len(azure_policies) == 0:
                change = True
            for identifier in azure_policies:
                permission = new_policies.get(identifier.id)
                if permission is None or len(azure_policies) != len(new_policies):
                    change = True
                    break
                match = ("rl" if permission == "read" else "racwdl")
                if match != identifier.access_policy.permission or identifier.access_policy.start != "2022-01-01T00:00:00.0000000Z"\
                or identifier.access_policy.expiry != "2100-01-01T00:00:00.0000000Z":
                    change = True
                    break
        return DiffResult(changes=change, replaces=replaces, stables=[], delete_before_replace=True)

    def update(self, _id: str, _olds: dict, _news: dict) -> UpdateResult:
        # It should be noted that update and create are nearly identical
        identifiers = {}
        policies = _news["policies"]
        for name, permission in policies.items():
            identifiers[name] = (self.read_access_policy if permission == "read" else self.write_access_policy)
        container_client = self.get_container_client(_news["connection_string"], _id)
        self.set_access_policy(container_client, "updating", _id, identifiers)
        _news["tokens"] = self.generate_tokens(policies, container_client)
        return UpdateResult(_news)

    def delete(self, _id: str, _props: dict) -> None:
        container_client = self.get_container_client(_props["connection_string"], _id)
        self.set_access_policy(container_client, "deleting", _id)

    @staticmethod
    def get_container_client(connection_string: str, container_name: str) -> ContainerClient:
        """Get a ContainerClient to be used for other calls"""
        try:
            service_client = BlobServiceClient.from_connection_string(connection_string)
            container_client = service_client.get_container_client(container_name)
        except Exception as error:
            raise Exception(f"Error getting container client for {container_name}.\nError: {error}") from error
        return container_client

    @staticmethod
    def set_access_policy(container_client: ContainerClient, verb: str, container_name: str, identifiers: dict = None) -> None:
        """Set Access Policies.  This could be create, update, or delete"""
        if identifiers is None:
            identifiers = {}
        try:
            container_client.set_container_access_policy(signed_identifiers=identifiers)
        except Exception as error:
            raise Exception(f"Error {verb} Access Policy for {container_name}.\nError: {error}") from error

    @staticmethod
    def generate_tokens(policies: dict, container_client: ContainerClient) -> dict:
        """Generate SAS tokens based upon the policy"""
        tokens = {}
        for policy in policies.keys():
            try:
                sas_token = generate_container_sas(container_client.account_name,
                                                   container_client.container_name,
                                                   container_client.credential.account_key,
                                                   policy_id=policy,
                                                   protocol="https")
                tokens[policy] = sas_token
            except Exception as error:
                raise Exception(f"Error generating SAS token for policy {policy} in container {container_client.container_name}.\nError: {error}")\
                    from error
        return tokens


def generate_connection_string(account_name: str, account_key: str):
    """Generate a connection string used to connect to a Storage Account"""
    return f"DefaultEndpointsProtocol=https;AccountName={account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"


def get_account_key(account_name: str, resource_group_name: str) -> Output[str]:
    """Get the account key for the Storage Account.  Output is flagged as secret"""
    return Output.secret(
        list_storage_account_keys_output(
            account_name=account_name,
            resource_group_name=resource_group_name,
        ).apply(lambda it: it.keys[0].value))


def get_connection_string(account_name: str, resource_group_name: str) -> Output[str]:
    """Generate a connection string used to connect to a Storage Account from Outputs"""
    return Output.all(account_name, get_account_key(account_name, resource_group_name)).apply(lambda it: generate_connection_string(*it))


class ContainerAccessPolicies(Resource):
    """A Pulumi Resource to call the ContainerAccessPolicyProvider for CRUD operations"""
    tokens: Output[dict]

    def __init__(self, name: str, args: ContainerAccessPolicyArgs, opts: Optional[ResourceOptions] = None) -> None:
        full_args = {"tokens": None, "connection_string": get_connection_string(args.storage_account, args.resource_group), **vars(args)}
        super().__init__(ContainerAccessPolicyProvider(), name, full_args, opts)
