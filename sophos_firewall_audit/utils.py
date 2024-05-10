''' Firewall Audit - utils.py

Copyright 2024 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

Utility functions used by main audit.
'''
import re

def html_red(text):
    """Apply red CSS style to text.

    Args:
        text (str): Text to surround with style
    """
    return f'<a style="color: red;">{text}</a>'

def html_yellow(text):
    """Apply red CSS style to text.

    Args:
        text (str): Text to surround with style
    """
    return f'<a style="color: yellow;">{text}</a>'

def html_status(audit_status):
    """Apply red or green CSS style based on audit status

    Args:
        audit_status (str): AUDIT_PASS or AUDIT_FAIL
    """
    if audit_status == "AUDIT_PASS":
        return f'<a style="color: lime; font-weight: bold;">{audit_status.strip("AUDIT_")}</a>'
    if audit_status == "AUDIT_FAIL":
        return f'<a style="color: red; font-weight: bold;">{audit_status.strip("AUDIT_")}</a>'
    
def format_diff(diff):
    """Remove lines with ---, +++, @@ and style diff lines in yellow.

    Args:
        diff (list): A list containing the diff

    Returns:
        list: formatted output
    """
    output = []
    for line in diff:
        patterns = ["-{3}", r"\+{3}", r"\@{2}"]
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                break
        if not match:
            if line.startswith("-") or line.startswith("+"):
                output.append(html_yellow(line))
            else:
                output.append(line)
    return output