package main

import "testing"

func TestExampleRejectsInvalidRequestBeforeDial(t *testing.T) {
	got, err := runExample()
	if err != nil {
		t.Fatal(err)
	}
	want := "invalid-rejected-before-dial=true\ndelivery=delivered\nresponse=review complete\n"
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
