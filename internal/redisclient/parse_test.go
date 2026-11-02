package redisclient

import (
	"bufio"
	"runtime"
	"strings"
	"testing"
)

func TestEncodeCommand(t *testing.T) {
	got := string(encodeCommand([]string{"EVALSHA", "abc", "1", "k", ""}))
	want := "*5\r\n$7\r\nEVALSHA\r\n$3\r\nabc\r\n$1\r\n1\r\n$1\r\nk\r\n$0\r\n\r\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// A hostile array header announcing ~16M elements followed by EOF must not
// make the client reserve memory for the announced length.
func TestHostileArrayHeaderDoesNotPreallocate(t *testing.T) {
	for _, hdr := range []string{"*16777215\r\n", "*16777215\r\n:1\r\n:2\r\n", "*1000000\r\n*1000000\r\n"} {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := readReply(bufio.NewReader(strings.NewReader(hdr)))
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("%q: truncated array accepted", hdr)
		}
		if d := after.TotalAlloc - before.TotalAlloc; d > 1<<20 {
			t.Errorf("%q: allocated %d bytes for a truncated reply", hdr, d)
		}
	}
	if _, err := readReply(bufio.NewReader(strings.NewReader("*16777217\r\n"))); err == nil ||
		!strings.Contains(err.Error(), "bad array length") {
		t.Errorf("over-cap array length: %v", err)
	}
	// A legitimately long array still parses (grows past the prealloc).
	var b strings.Builder
	b.WriteString("*3000\r\n")
	for i := 0; i < 3000; i++ {
		b.WriteString(":7\r\n")
	}
	rep, err := readReply(bufio.NewReader(strings.NewReader(b.String())))
	if err != nil || len(rep.Array) != 3000 || rep.Array[2999].Int != 7 {
		t.Fatalf("long array: %v %d", err, len(rep.Array))
	}
}

func TestReadReplyForms(t *testing.T) {
	longErr := "-ERR " + strings.Repeat("x", 10000) + "\r\n"
	in := ":42\r\n:-7\r\n:+3\r\n:12345678901234567890\r\n:9223372036854775807\r\n+OK\r\n$5\r\nhello\r\n$-1\r\n*-1\r\n" +
		"*3\r\n:1\r\n*2\r\n$1\r\na\r\n:2\r\n+x\r\n" + longErr + ":1x\r\n$-5\r\n"
	r := bufio.NewReader(strings.NewReader(in))
	next := func() *Reply {
		t.Helper()
		rep, err := readReply(r)
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		return rep
	}
	if rep := next(); rep.Type != ':' || rep.Int != 42 {
		t.Errorf("int: %+v", rep)
	}
	if rep := next(); rep.Int != -7 {
		t.Errorf("neg int: %+v", rep)
	}
	if rep := next(); rep.Int != 3 {
		t.Errorf("plus int: %+v", rep)
	}
	if _, err := readReply(r); err == nil {
		t.Error("overflowing integer accepted")
	}
	if rep := next(); rep.Int != 9223372036854775807 {
		t.Errorf("max int: %+v", rep)
	}
	if rep := next(); rep.Type != '+' || rep.Str != "OK" {
		t.Errorf("simple: %+v", rep)
	}
	if rep := next(); rep.Type != '$' || rep.Str != "hello" {
		t.Errorf("bulk: %+v", rep)
	}
	if rep := next(); !rep.IsNil || rep.Type != '$' {
		t.Errorf("nil bulk: %+v", rep)
	}
	if rep := next(); !rep.IsNil || rep.Type != '*' {
		t.Errorf("nil array: %+v", rep)
	}
	rep := next()
	if rep.Type != '*' || len(rep.Array) != 3 || rep.Array[0].Int != 1 || len(rep.Array[1].Array) != 2 ||
		rep.Array[1].Array[0].Str != "a" || rep.Array[1].Array[1].Int != 2 || rep.Array[2].Str != "x" {
		t.Errorf("nested array: %+v", rep)
	}
	if rep := next(); rep.Type != '-' || len(rep.Str) != 4+10000 {
		t.Errorf("long error line: type %q len %d", rep.Type, len(rep.Str))
	}
	if _, err := readReply(r); err == nil || !strings.Contains(err.Error(), "bad integer") {
		t.Errorf("bad int: %v", err)
	}
	if _, err := readReply(r); err == nil || !strings.Contains(err.Error(), "bad bulk length") {
		t.Errorf("bad bulk length: %v", err)
	}
}
