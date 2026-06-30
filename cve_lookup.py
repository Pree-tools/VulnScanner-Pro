# Demo CVE database
# Later we'll replace this with a live CVE API.

CVE_DATABASE = {

    "OpenSSH": [
        {
            "cve": "CVE-2016-0777",
            "severity": "HIGH",
            "description": "Information Disclosure"
        },
        {
            "cve": "CVE-2018-15473",
            "severity": "MEDIUM",
            "description": "Username Enumeration"
        }
    ],

    "Apache": [
        {
            "cve": "CVE-2021-41773",
            "severity": "CRITICAL",
            "description": "Path Traversal"
        }
    ],

    "nginx": [
        {
            "cve": "CVE-2021-23017",
            "severity": "HIGH",
            "description": "DNS Resolver Vulnerability"
        }
    ]
}


def lookup_cve(product):

    for key in CVE_DATABASE:

        if key.lower() in product.lower():
            return CVE_DATABASE[key]

    return []