//go:build !darwin

package notifier

func Notify(title, message string) {}
