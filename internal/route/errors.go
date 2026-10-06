package route

import (
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/requestinfo"
)

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
