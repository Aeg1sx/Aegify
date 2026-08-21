package com.acme.orders

@RestController
@RequestMapping(path = ["/orders"])
class OrderController(private val orderService: OrderService) {
    @GetMapping(path = ["/{id}"])
    @PreAuthorize("hasAuthority('orders:read')")
    fun getOrder(@PathVariable id: String): String = orderService.getOrder(id)

    @PostMapping(path = ["/{id}/cancel"])
    @PreAuthorize("hasAuthority('orders:cancel')")
    suspend fun cancelOrder(@PathVariable id: String, @RequestBody request: CancelOrder): String = orderService.cancelOrder(id)
}

data class CancelOrder(val reason: String)
