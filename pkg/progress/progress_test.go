/*
 * © 2024 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package progress

import (
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBeginProgress(t *testing.T) {
	channel := make(chan ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	progress.BeginWithMessage("title", "message")

	assert.Equal(
		t,
		ProgressParams{
			Token: progress.token,
			Value: nil,
		},
		<-channel,
	)

	assert.Equal(
		t,
		ProgressParams{
			Token: progress.token,
			Value: WorkDoneProgressBegin{
				WorkDoneProgressKind: WorkDoneProgressKind{Kind: "begin"},
				Title:                "title",
				Cancellable:          true,
				Message:              "message",
				Percentage:           1,
			},
		},
		<-channel,
	)
}

func TestReportProgress(t *testing.T) {
	output := ProgressParams{
		Token: "token",
		Value: WorkDoneProgressReport{
			WorkDoneProgressKind: WorkDoneProgressKind{Kind: "report"},
			Percentage:           10,
		},
	}
	channel := make(chan ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	workProgressReport, ok := output.Value.(WorkDoneProgressReport)
	require.True(t, ok)
	progress.Report(workProgressReport.Percentage)

	assert.Equal(t, output, <-channel)
}

func TestEndProgress(t *testing.T) {
	output := ProgressParams{
		Token: "token",
		Value: WorkDoneProgressEnd{
			WorkDoneProgressKind: WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}

	channel := make(chan ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	workProgressEnd, ok := output.Value.(WorkDoneProgressEnd)
	require.True(t, ok)
	progress.EndWithMessage(workProgressEnd.Message)

	assert.Equal(t, output, <-channel)
}

func TestEndProgressTwice(t *testing.T) {
	output := ProgressParams{
		Value: WorkDoneProgressEnd{
			WorkDoneProgressKind: WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}

	channel := make(chan ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	workProgressEnd, ok := output.Value.(WorkDoneProgressEnd)
	require.True(t, ok)
	progress.EndWithMessage(workProgressEnd.Message)

	assert.Panics(t, func() {
		progress.EndWithMessage(workProgressEnd.Message)
	})
}
