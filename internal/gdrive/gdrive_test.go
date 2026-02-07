package gdrive

import "testing"

func TestExtractFileID(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "file/d/ URL",
			url:  "https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/view?usp=sharing",
			want: "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
		},
		{
			name: "open?id= URL",
			url:  "https://drive.google.com/open?id=1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
			want: "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
		},
		{
			name: "Google Docs URL",
			url:  "https://docs.google.com/document/d/1abc-def_GHI/edit",
			want: "1abc-def_GHI",
		},
		{
			name: "Google Sheets URL",
			url:  "https://docs.google.com/spreadsheets/d/1abc-def_GHI/edit#gid=0",
			want: "1abc-def_GHI",
		},
		{
			name: "non-Drive URL",
			url:  "https://www.dropbox.com/s/abc123/file.png",
			want: "",
		},
		{
			name: "empty string",
			url:  "",
			want: "",
		},
		{
			name: "not a URL",
			url:  "not a url",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFileID(tt.url)
			if got != tt.want {
				t.Errorf("ExtractFileID(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsDriveURL(t *testing.T) {
	if !IsDriveURL("https://drive.google.com/file/d/abc123/view") {
		t.Error("expected true for Drive URL")
	}
	if IsDriveURL("https://www.dropbox.com/s/abc/file.png") {
		t.Error("expected false for Dropbox URL")
	}
}
