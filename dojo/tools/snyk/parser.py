import json

from dojo.models import Finding, Endpoint
from django.utils.encoding import smart_text, force_str

class SnykParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        try:
            tree = json.load(json_output)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}

        for node in tree:
            item = get_item(node, test)
            unique_key = node['title'] + str(node['path'])
            items[unique_key] = item

        return items.values()


def get_item(item_node, test):

    # vulnerable versions can be in string format for a single vulnerable version, or an array for multiple versions.
    if isinstance(item_node['vulnerable_versions'], list)
        vulnerable_versions = ", ".join(item_node['path'])
    else
        vulnerable_versions = item_node['vulnerable_versions']



    finding = Finding(title=item_node['title'] + " - " + "(" + item_node['name'] + ", " + item_node['version'] + ")",
                      test=test,
                      severity=severity.title(),
                      description=item_node['description'] + "\n Vulnerable Module: "
                      + item_node['moduleName'] + "\n Vulnerable Versions: "
                      + vulnerable_versions + "\n Current Version: "
                      + str(item_node['version']) + "\n Vulnerable Path: " + " > ".join(item_node['from']),
                      mitigation=semver.unaffected,
                      references=item_node['advisory'],
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      impact="No impact provided")

    return finding