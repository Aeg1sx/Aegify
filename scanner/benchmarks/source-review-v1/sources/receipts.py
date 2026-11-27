def shipping_label(order):
    return {"order_id": order.id, "customer_email": order.customer_email}


def order_summary(order):
    return {"order_id": order.id, "status": order.status}


def partner_receipt(order, formatter):
    return formatter(order)
