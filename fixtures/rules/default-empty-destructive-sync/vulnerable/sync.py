def reconcile_page(response, cache):
    widgets = response.get("widgets", [])
    seen_ids = {widget["id"] for widget in widgets}

    for stored_widget in cache.all():
        if stored_widget.id not in seen_ids:
            cache.delete_item(stored_widget)
