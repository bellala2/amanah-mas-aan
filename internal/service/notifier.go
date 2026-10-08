package service

import (
	"context"
	"log/slog"
)

// Notifier mengirim OTP ke user. Ganti implementasinya dengan provider WhatsApp
// (Fonnte / Twilio / WABA) dan SMTP/SES untuk email.
type Notifier interface {
	SendOTP(ctx context.Context, channel, destination, code, purpose string) error
}

// LogNotifier hanya untuk development: kode OTP dicetak ke log bila ShowCode true.
type LogNotifier struct {
	Log      *slog.Logger
	ShowCode bool
}

func (n LogNotifier) SendOTP(_ context.Context, channel, destination, code, purpose string) error {
	if n.ShowCode {
		n.Log.Info("OTP (dev notifier)", "channel", channel, "to", destination, "purpose", purpose, "code", code)
	} else {
		n.Log.Info("OTP dispatched (dev notifier)", "channel", channel, "to", destination, "purpose", purpose)
	}
	return nil
}

// NewLogNotifier membuat notifier development (log). Ganti di main.go saat integrasi provider asli.
func NewLogNotifier(log *slog.Logger, showCode bool) Notifier {
	return LogNotifier{Log: log, ShowCode: showCode}
}
