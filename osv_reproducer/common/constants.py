
# TODO: User-Agent should be dynamic

USER_AGENT_HEADERS = {
    'User-Agent': f'osv-reproducer/1.0.0 Python/3.10'
}

HTTP_HEADERS = {
    'Accept': 'application/json', 'Content-type': 'application/json', 'User-Agent': USER_AGENT_HEADERS['User-Agent']
}