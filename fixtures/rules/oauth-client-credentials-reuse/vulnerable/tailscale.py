import requests


def _mint_oauth_bearer(
    api_session: requests.Session,
    base_url: str,
    client_id: str,
    client_secret: str,
) -> str:
    response = api_session.post(
        f"{base_url.rstrip('/')}/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=(10, 30),
    )
    response.raise_for_status()
    return response.json()["access_token"]


def start_tailscale_ingestion(config) -> None:
    api_session = requests.session()
    bearer_token = _mint_oauth_bearer(
        api_session,
        config.tailscale_base_url,
        config.tailscale_oauth_client_id,
        config.tailscale_oauth_client_secret,
    )
    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})

    cartography.intel.tailscale.tailnets.sync(
        api_session,
        org=config.tailscale_org,
    )
    cartography.intel.tailscale.users.sync(
        api_session,
        org=config.tailscale_org,
    )
    cartography.intel.tailscale.devices.sync(
        api_session,
        org=config.tailscale_org,
    )
