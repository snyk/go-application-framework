package presenters

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/net/html"
)

type ElementCallback func(tagName, cssClass, originalContent string) string

type HTMLpresenter struct {
	Callback ElementCallback
}

func NewHTMLPresenter(callback ElementCallback) *HTMLpresenter {
	return &HTMLpresenter{
		Callback: callback,
	}
}

func getTextContent(n *html.Node) string {
	var sb strings.Builder
	var f func(*html.Node)
	f = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}

		if node.Type == html.ElementNode && (node.Data == "p" || node.Data == "div" || node.Data == "br" || node.Data == "li") {
			if sb.Len() > 0 && sb.String()[sb.Len()-1] != ' ' && sb.String()[sb.Len()-1] != '\n' {
				sb.WriteString(" ") // Add a space between block elements' text
			}
		}

		for c := node.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	str := sb.String()
	return strings.TrimSuffix(str, " ")
}

func replaceChildren(parent *html.Node, newContent string) {
	for c := parent.FirstChild; c != nil; {
		next := c.NextSibling
		parent.RemoveChild(c)
		c = next
	}

	if newContent != "" {
		newNode := &html.Node{
			Type: html.TextNode,
			Data: newContent,
		}
		parent.AppendChild(newNode)
	}
}

func (p *HTMLpresenter) Present(htmlString string) (string, error) {
	doc, err := html.Parse(strings.NewReader(htmlString))
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	var traverseAndModify func(*html.Node)
	traverseAndModify = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tagName := n.Data
			var cssClass string
			var hasClassAttribute bool = false

			for _, attr := range n.Attr {
				if attr.Key == "class" {
					cssClass = attr.Val
					hasClassAttribute = true
					break
				}
			}

			if hasClassAttribute {
				originalContent := getTextContent(n)
				if p.Callback != nil {
					newContent := p.Callback(tagName, cssClass, originalContent)
					replaceChildren(n, newContent)
				}
				return
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverseAndModify(c)
		}
	}

	traverseAndModify(doc)

	finalPlainText := getTextContent(doc)

	return finalPlainText, nil
}

func HtmlToAnsi(tag, cssClass, originalContent string) string {
	switch cssClass {
	case "prompt-help":
		return lipgloss.NewStyle().Faint(true).Render(originalContent)
	default:
		return originalContent
	}
}

func IsHtml(str string) bool {
	if !strings.Contains(str, "<") || !strings.Contains(str, ">") {
		return false
	}
	return true
}
