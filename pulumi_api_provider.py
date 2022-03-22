"""A Pulumi Dynamic Provider for the Pulumi API"""

import json
import os
from typing import Any, Optional
from dataclasses import dataclass
from pulumi import Input, Output, ResourceOptions, RunError
from pulumi.dynamic import ResourceProvider, CreateResult, DiffResult, UpdateResult, Resource
import requests


def _detect_token(url: str):
    if "PULUMI_ACCESS_TOKEN" in os.environ:
        return os.environ["PULUMI_ACCESS_TOKEN"]

    pulumi_home = os.path.expanduser(os.environ.get("PULUMI_HOME", "~/.pulumi"))
    with open(os.path.join(pulumi_home, "credentials.json"), encoding="utf-8") as file_handle:
        cred_json = json.load(file_handle)

    token = cred_json["accounts"][url]["accessToken"]
    if token:
        return token
    raise RunError("Token not found. Run `pulumi login` first.")


@dataclass
class PulumiTagArgs:
    """Arguments which will be passed to the PulumiTagProvider"""
    tag_name: Input[str]
    tag_value: Input[str]
    project: Input[str]
    stack: Input[str]


class PulumiTagProvider(ResourceProvider):
    """A Dynamic Provider as documented at https://www.pulumi.com/docs/intro/concepts/resources/dynamic-providers/
    Specifically it makes requests to the Pulumi API to manage stack tags as documented at
    https://www.pulumi.com/docs/reference/service-rest-api/#stack-tags
    """
    URL = "https://api.pulumi.com"
    org = "yourorg"
    timeout = 3
    token = _detect_token(URL)

    def create(self, props: Any) -> CreateResult:
        project = props["project"]
        stack = props["stack"]
        url = f"{self.URL}/api/stacks/{self.org}/{project}/{stack}/tags"
        head = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.pulumi+8",
            "Content-Type": "application/json",
        }
        data = {
            "name": props["tag_name"],
            "value": props["tag_value"],
        }

        with requests.Session() as session:
            response = session.post(url, json=data, headers=head, timeout=self.timeout, verify=True)
            if response.status_code != 204:
                raise Exception(f"Error creating tag: {response.text}")

        return CreateResult(props["tag_name"], {"value": props["tag_value"], "url": url})

    def diff(self, _id: str, _olds: Any, _news: Any) -> DiffResult:
        project = _news["project"]
        stack = _news["stack"]
        url = f"{self.URL}/api/stacks/{self.org}/{project}/{stack}"
        head = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.pulumi+8",
            "Content-Type": "application/json",
        }

        with requests.Session() as session:
            response = session.get(url, headers=head, timeout=self.timeout, verify=True)
            if response.status_code != 200:
                raise Exception(f"Error reading stack tag info: {response.text}")

        tags = response.json()["tags"]
        tag_exists = _id in tags

        change = True
        replaces = []
        if tag_exists:
            if tags[_id] == _news["tag_value"]:
                change = False
            else:
                replaces = ["tag_value"]

        stables = []
        if _id == _news["tag_name"]:
            stables.append("tag_name")

        return DiffResult(changes=change, replaces=replaces, stables=stables, delete_before_replace=True)

    def update(self, _id: str, _olds: Any, _news: Any) -> UpdateResult:
        # API does not support update so this is a create.
        # Should only get called if state thinks tag exists but it does not
        project = _news["project"]
        stack = _news["stack"]
        url = f"{self.URL}/api/stacks/{self.org}/{project}/{stack}/tags"
        head = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.pulumi+8",
            "Content-Type": "application/json",
        }
        data = {
            "name": _news["tag_name"],
            "value": _news["tag_value"],
        }

        with requests.Session() as session:
            response = session.post(url, json=data, headers=head, timeout=self.timeout, verify=True)
            if response.status_code != 204:
                raise Exception(f"Error creating tag: {response.text}")

        return UpdateResult({"value": _news["tag_value"], "url": url})

    def delete(self, _id: str, _props: Any) -> None:
        url_base = _props["url"]
        url = f"{url_base}/{_id}"
        head = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.pulumi+8",
            "Content-Type": "application/json",
        }

        with requests.Session() as session:
            response = session.delete(url, headers=head, timeout=self.timeout, verify=True)
            if response.status_code != 204:
                raise Exception(f"Error deleting tag: {response.text}")


class PulumiTag(Resource):
    """A Pulumi Resource to call the PulumiTagProvider for CRUD operations"""
    name: Output[str]
    value: Output[str]

    def __init__(self, name: str, args: PulumiTagArgs, opts: Optional[ResourceOptions] = None) -> None:
        full_args = {"name": None, "value": None, **vars(args)}

        super().__init__(PulumiTagProvider(), name, full_args, opts)
