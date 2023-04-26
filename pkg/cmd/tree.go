package cmd

import (
	"fmt"

	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/cobra"
)

type cmdTree struct {
	name       string
	children   map[string]*cmdTree
	workflowID workflow.Identifier
}

func newNode(name string) *cmdTree {
	return &cmdTree{
		name:     name,
		children: map[string]*cmdTree{},
	}
}

func (n *cmdTree) add(parts []string, workflowID workflow.Identifier) {
	if len(parts) < 1 {
		n.workflowID = workflowID
		return
	}
	head := parts[0]
	child, ok := n.children[head]
	if !ok {
		child = newNode(head)
		n.children[head] = child
	}
	child.add(parts[1:], workflowID)
}

func (n *cmdTree) cmd(engine workflow.Engine) *cobra.Command {
	var cmd *cobra.Command
	if n.workflowID == nil {
		cmd = newEmptyCommand(n.name)
	} else {
		cmd = newWorkflowCommand(n.name, engine, n.workflowID)
	}
	for _, child := range n.children {
		cmd.AddCommand(child.cmd(engine))
	}
	return cmd
}

func runEmpty(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("no workflow for command")
}

func newEmptyCommand(name string) *cobra.Command {
	return &cobra.Command{
		Use:                name,
		Hidden:             true,
		RunE:               runEmpty,
		DisableFlagParsing: true,
	}
}

func newWorkflowCommand(name string, engine workflow.Engine, id workflow.Identifier) *cobra.Command {
	w, _ := engine.GetWorkflow(id)
	cmd := &cobra.Command{
		Use:    name,
		Hidden: !w.IsVisible(),
		RunE: func(cmd *cobra.Command, args []string) error {
			config := engine.GetConfiguration()
			if err := config.AddFlagSet(cmd.Flags()); err != nil {
				return err
			}
			data, err := engine.Invoke(id)
			if err != nil {
				return err
			}
			_, err = engine.InvokeWithInput(localworkflows.WORKFLOWID_OUTPUT_WORKFLOW, data)
			return err
		},
	}
	options := w.GetConfigurationOptions()
	flagset := workflow.FlagsetFromConfigurationOptions(options)
	if flagset != nil {
		cmd.Flags().AddFlagSet(flagset)
	}
	return cmd
}
