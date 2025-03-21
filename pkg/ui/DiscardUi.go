package ui

type DiscardUi struct {
}

func (d DiscardUi) Output(_ interface{}) error {
	return nil
}

func (d DiscardUi) OutputError(_ error, _ ...Opts) error {
	return nil
}

func (d DiscardUi) NewProgressBar() ProgressBar {
	return nil
}

func (d DiscardUi) Input(_ string) (string, error) {
	return "", nil
}

func NewDiscardUi() UserInterface {
	return &DiscardUi{}
}

var _ UserInterface = (*DiscardUi)(nil)
