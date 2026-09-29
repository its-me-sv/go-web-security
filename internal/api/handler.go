package api

import (
	"net/http"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
)

type orderItemResponse struct {
	ProductID   int64  `json:"product_id"`
	ProductName string `json:"product_name"`
	Quantity    int64  `json:"quantity"`
	PriceCents  int64  `json:"price_cents"`
}

type Handler struct {
	accountStore      *accounts.Store
	orderStore        *orders.Store
	productStore      *storefront.Store
	apiStore          *Store
	logger            *logging.Logger
	maxProductResults int64
}

func NewHandler(accountStore *accounts.Store, orderStore *orders.Store, productStore *storefront.Store, apiStore *Store, logger *logging.Logger, maxProductResults int) *Handler {
	return &Handler{
		accountStore: accountStore, orderStore: orderStore, productStore: productStore, apiStore: apiStore,
		logger: logger, maxProductResults: int64(maxProductResults),
	}
}

func (handler *Handler) AccountOrders(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orders, err := handler.orderStore.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	httpx.RespondWithJSON(
		responseWriter,
		http.StatusOK,
		map[string]any{"orders": getOrderResponseFromOrder(orders)})
}

func (handler *Handler) Order(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orderID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || order.UserID != current.User.ID {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	items, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	itemResponses := make([]orderItemResponse, 0, len(items))
	for _, item := range items {
		itemResponses = append(itemResponses, orderItemResponse{ProductID: item.ProductID, ProductName: item.ProductName, Quantity: item.Quantity, PriceCents: item.PriceCents})
	}
	httpx.RespondWithJSON(
		responseWriter,
		http.StatusOK,
		map[string]any{"order": orderResponse{
			ID:         order.ID,
			Status:     order.Status,
			TotalCents: order.TotalCents,
			CreatedAt:  order.CreatedAt,
		}, "items": itemResponses})
}

func (handler *Handler) Products(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Access-Control-Allow-Origin", "*")

	products, err := handler.productStore.ListProducts(request.Context(), handler.maxProductResults)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	httpx.RespondWithJSON(
		responseWriter,
		http.StatusOK,
		map[string]any{"products": getProductResponseFromProduct(products)})
}

func (handler *Handler) ProductPreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) WarehouseOrders(responseWriter http.ResponseWriter, request *http.Request) {
	apiKey := request.Header.Get("X-API-Key")
	if apiKey == "" {
		httpx.RespondWithError(responseWriter, http.StatusUnauthorized, "Missing API key")
		return
	}
	srcKey, found, err := handler.apiStore.FindKey(request.Context(), apiKey)
	if !found {
		httpx.RespondWithError(responseWriter, http.StatusUnauthorized, "Missing API key")
		return
	}
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !strings.Contains(srcKey.Scope, "orders:read") {
		httpx.RespondWithError(responseWriter, http.StatusForbidden, "Missing required scope")
		return
	}
	orders, err := handler.orderStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"integration": "Warehouse Fulfillment Integration",
		"orders":      getOrderResponseFromOrder(orders),
	})
}

func (handler *Handler) requireAuthentication(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	httpx.RespondWithError(responseWriter, http.StatusInternalServerError, err.Error())
}

type productResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ImagePath   string `json:"image_path"`
	PriceCents  int64  `json:"price_cents"`
}

func getProductResponseFromProduct(products []storefront.Product) []productResponse {
	result := make([]productResponse, len(products))
	for i, product := range products {
		result[i] = productResponse{
			ID:          product.ID,
			Name:        product.Name,
			Description: product.Description,
			ImagePath:   product.ImagePath,
			PriceCents:  product.PriceCents,
		}
	}
	return result
}

type orderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

func getOrderResponseFromOrder(orders []orders.Order) []orderResponse {
	result := make([]orderResponse, len(orders))
	for i, order := range orders {
		result[i] = orderResponse{
			ID:         order.ID,
			Status:     order.Status,
			TotalCents: order.TotalCents,
			CreatedAt:  order.CreatedAt,
		}
	}
	return result
}
