from typing import Any

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
        headers={"Authorization": None},
        timeout=(10, 30),
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _attach_oauth_refresh(
    api_session: requests.Session,
    base_url: str,
    client_id: str,
    client_secret: str,
) -> None:
    token_url = f"{base_url.rstrip('/')}/oauth/token"
    retried_request_ids: set[int] = set()

    def _refresh_on_unauthorized(
        response: requests.Response,
        *args: Any,
        **kwargs: Any,
    ) -> requests.Response:
        if response.status_code != 401:
            return response
        if response.request.url == token_url:
            return response
        request_id = id(response.request)
        if request_id in retried_request_ids:
            return response
        new_token = _mint_oauth_bearer(api_session, base_url, client_id, client_secret)
        api_session.headers["Authorization"] = f"Bearer {new_token}"
        retried = response.request.copy()
        retried.headers["Authorization"] = f"Bearer {new_token}"
        retried_request_ids.add(id(retried))
        return api_session.send(retried, **kwargs)

    api_session.hooks["response"].append(_refresh_on_unauthorized)


def start_tailscale_ingestion(config) -> None:
    api_session = requests.session()
    bearer_token = _mint_oauth_bearer(
        api_session,
        config.tailscale_base_url,
        config.tailscale_oauth_client_id,
        config.tailscale_oauth_client_secret,
    )
    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})
    _attach_oauth_refresh(
        api_session,
        config.tailscale_base_url,
        config.tailscale_oauth_client_id,
        config.tailscale_oauth_client_secret,
    )
    cartography.intel.tailscale.tailnets.sync(api_session, org=config.tailscale_org)
    cartography.intel.tailscale.users.sync(api_session, org=config.tailscale_org)
