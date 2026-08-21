package com.acme.orders

@Service
class OrderService {
    fun getOrder(id: String): String = id
    fun cancelOrder(id: String): String = id
}
