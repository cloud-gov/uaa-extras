import re


def email_valid_for_domains(address, domains):
    """
    check if the email address's domain appears to be a hostname within the provided domains
    """
    address, address_domain = address.split("@")
    return any(host_valid_for_domain(address_domain, domain) for domain in domains)


def host_valid_for_domain(host, domain):
    valid_parts = domain.split(".")
    host_parts = host.split(".")
    overlap = host_parts[-1 * len(valid_parts) :]
    return overlap == valid_parts


def email_username_valid(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email)
