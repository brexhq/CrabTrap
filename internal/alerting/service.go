package alerting

// Service is the alerting service. In this layer it only provides sender
// registration and lookup for channel type validation. The dispatch logic
// is added in a subsequent PR.
type Service struct {
	senders map[string]Sender
}

func NewService() *Service {
	return &Service{senders: make(map[string]Sender)}
}

func (s *Service) RegisterSender(channelType string, sender Sender) {
	s.senders[channelType] = sender
}

func (s *Service) SenderFor(channelType string) Sender {
	return s.senders[channelType]
}
