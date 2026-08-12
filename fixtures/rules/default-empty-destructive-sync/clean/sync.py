def reconcile_page(response, cache):
    widgets = response["widgets"]
    if not isinstance(widgets, list):
        raise ValueError("widgets must be a list")

    seen_ids = {widget["id"] for widget in widgets}
    for stored_widget in cache.all():
        if stored_widget.id not in seen_ids:
            cache.delete(stored_widget)


def summarize_optional_metadata(response):
    labels = response.get("labels", [])
    return sorted(labels)
