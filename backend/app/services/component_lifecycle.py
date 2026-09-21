"""A component override takes precedence over its product's shared support dates."""


def effective_component_lifecycle(component):
    if component.support_end_date is not None:
        return component.support_end_date, component.lifecycle_source_url, "component"
    product = component.product_release
    if product:
        end_date = product.security_end_date or product.support_end_date or product.eol_date
        if end_date is not None:
            return end_date, product.lifecycle_source_url, "product"
    return None, None, "unknown"
