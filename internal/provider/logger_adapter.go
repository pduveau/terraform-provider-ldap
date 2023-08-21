package provider

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"io"
)

// TFLoggerAdapter is a Writer which is provided by the ldap package as a logger and logs using tflog.Debug.
type TFLoggerAdapter struct {
	ctx context.Context
}

func (T TFLoggerAdapter) Write(p []byte) (n int, err error) {
	tflog.Debug(T.ctx, fmt.Sprintf("LDAP log output: %s", p))
	return len(p), nil
}

var _ io.Writer = TFLoggerAdapter{}
