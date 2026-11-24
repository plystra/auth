package route

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/requestinfo"
)

// WriteSCIMError preserves the SCIM error document even before route dispatch.
func WriteSCIMError(w http.ResponseWriter, err error) {
	var public *apierr.Error
	if !errors.As(err, &public) {
		public = apierr.New("temporarily_unavailable", "SCIM operation is unavailable")
	}
	status, scimType := public.GetStatus(), ""
	switch public.Code {
	case "invalid_filter":
		status, scimType = http.StatusBadRequest, "invalidFilter"
	case "scim_no_target":
		status, scimType = http.StatusBadRequest, "noTarget"
	case "scim_mutability":
		status, scimType = http.StatusBadRequest, "mutability"
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  public.Message, "status": strconv.Itoa(status), "scimType": scimType,
	})
}

func init() {
	// Huma calls these package-level constructors for decoder and validation
	// failures before an operation handler runs. Keep those failures on Auth's
	// public error contract instead of leaking Huma's problem document.
	huma.NewError = newHumaError
	huma.NewErrorWithContext = newHumaErrorWithContext
}

func newHumaError(status int, message string, errs ...error) huma.StatusError {
	return newHumaErrorWithContext(nil, status, message, errs...)
}

func newHumaErrorWithContext(ctx huma.Context, status int, message string, errs ...error) huma.StatusError {
	code := "VALIDATION_FAILED"
	publicStatus := http.StatusBadRequest
	if status >= http.StatusInternalServerError {
		code = "UNAVAILABLE"
		message = "The service is temporarily unavailable."
		publicStatus = http.StatusServiceUnavailable
	}
	public := apierr.WithStatus(apierr.New(code, message), publicStatus)
	if ctx != nil {
		public = apierr.WithRequestID(public, requestinfo.Get(ctx.Context()).ID)
	}
	if details := humaValidationDetails(errs); len(details) > 0 {
		public.Details = details
	}
	return public
}

func humaValidationDetails(errs []error) []map[string]string {
	details := make([]map[string]string, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		var detailer huma.ErrorDetailer
		if errors.As(err, &detailer) {
			detail := detailer.ErrorDetail()
			item := map[string]string{"message": detail.Message}
			if detail.Location != "" {
				item["location"] = detail.Location
			}
			details = append(details, item)
			continue
		}
		details = append(details, map[string]string{"message": "invalid input"})
	}
	return details
}
