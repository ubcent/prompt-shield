package session

import "testing"

func TestStoreSetGetDelete(t *testing.T) {
	store := NewStore()
	mapping := map[string]string{"[EMAIL_1]": "john@example.com"}

	store.Set("abc", mapping)
	sess, ok := store.Get("abc")
	if !ok {
		t.Fatal("expected session")
	}
	if sess.Mapping["[EMAIL_1]"] != "john@example.com" {
		t.Fatalf("unexpected mapping: %#v", sess.Mapping)
	}

	mapping["[EMAIL_1]"] = "changed@example.com"
	if sess.Mapping["[EMAIL_1]"] != "john@example.com" {
		t.Fatal("store should keep a copy of mapping")
	}

	store.Delete("abc")
	if _, ok := store.Get("abc"); ok {
		t.Fatal("session should be deleted")
	}
}

func TestGenerateID(t *testing.T) {
	id1 := GenerateID()
	id2 := GenerateID()
	if id1 == "" || id2 == "" {
		t.Fatal("expected non-empty IDs")
	}
	if id1 == id2 {
		t.Fatal("expected unique IDs")
	}
}
