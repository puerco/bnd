package cmd

import (
	"testing"

	"github.com/carabiner-dev/bnd/internal/git"
	"github.com/stretchr/testify/require"
)

func TestVCSBuilder(t *testing.T) {
	for _, tc := range []struct {
		name         string
		opts         commitOptions
		headDetails  git.HeadDetails
		remoteReader func(string) (map[string]string, error)
		mustErr      bool
		expect       string
	}{
		{
			"preurl",
			commitOptions{repoURL: "https://github.com/example/test"},
			git.HeadDetails{CommitSHA: "d538e1d143d9c28b646a9dccc60f9bab899425f6"},
			func(s string) (map[string]string, error) {
				return map[string]string{"origin": "https://github.com/puerco/lab"}, nil
			},
			false,
			"git+https://github.com/example/test@d538e1d143d9c28b646a9dccc60f9bab899425f6",
		},
		{
			"ssh-source",
			commitOptions{},
			git.HeadDetails{CommitSHA: "d538e1d143d9c28b646a9dccc60f9bab899425f6"},
			func(s string) (map[string]string, error) {
				return map[string]string{"origin": "git@github.com:puerco/lab.git"}, nil
			},
			false,
			"git+ssh://github.com/puerco/lab@d538e1d143d9c28b646a9dccc60f9bab899425f6",
		},
		{
			"remoteurl-no-preference",
			commitOptions{},
			git.HeadDetails{CommitSHA: "d538e1d143d9c28b646a9dccc60f9bab899425f6"},
			func(s string) (map[string]string, error) {
				return map[string]string{
					"origin": "https://github.com/puerco/lab",
				}, nil
			},
			false,
			"git+https://github.com/puerco/lab@d538e1d143d9c28b646a9dccc60f9bab899425f6",
		},
		{
			"remoteurl-honor-opt",
			commitOptions{remoteNames: []string{"honk"}},
			git.HeadDetails{CommitSHA: "d538e1d143d9c28b646a9dccc60f9bab899425f6"},
			func(s string) (map[string]string, error) {
				return map[string]string{
					"origin":   "https://github.com/puerco/lab",
					"upstream": "https://github.com/kubernetes/lab",
					"honk":     "https://github.com/honk/lab",
				}, nil
			},
			false,
			"git+https://github.com/honk/lab@d538e1d143d9c28b646a9dccc60f9bab899425f6",
		},
	} {
		locator, err := makeVCSLocator(&tc.opts, &tc.headDetails, tc.remoteReader)
		if tc.mustErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.Equal(t, tc.expect, locator)
	}
}
