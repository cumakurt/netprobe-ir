package detectionquality

import "testing"

func TestQualityMetricsAndPersistence(t *testing.T) {
	path := t.TempDir() + "/quality.json"
	s := New(path)
	if err := s.Record(Run{Label: "malicious", ExpectedRules: []string{"R1"}, Observed: map[string]int{"R1": 1}, Frames: 100, ElapsedMS: 10}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Run{Label: "benign", Benign: true, Observed: map[string]int{"R1": 1, "R2": 2}, Frames: 100, ElapsedMS: 10}); err != nil {
		t.Fatal(err)
	}
	x := s.Summary()
	if x.Runs != 2 || len(x.Rules) != 2 {
		t.Fatalf("summary=%#v", x)
	}
	var r1 RuleMetric
	for _, r := range x.Rules {
		if r.RuleID == "R1" {
			r1 = r
		}
	}
	if r1.TruePositive != 1 || r1.FalsePositive != 1 {
		t.Fatalf("r1=%#v", r1)
	}
	s2 := New(path)
	if len(s2.Runs(10)) != 2 {
		t.Fatal("persistence failed")
	}
}
