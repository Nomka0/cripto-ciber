package generator

import (
	"errors"
	"math"
	"math/rand/v2"
	"testing"
)

func TestUniformDistribution(t *testing.T) {
	const minVal = 0.0
	const maxVal = 5.0
	const samples = 100_000

	gen, err := NewUniformGradeGenerator(minVal, maxVal)
	if err != nil {
		t.Fatalf("unexpected error creating generator: %v", err)
	}

	var sum float64
	observedMin := math.MaxFloat64
	observedMax := -math.MaxFloat64

	for i := 0; i < samples; i++ {
		grade := gen.GenerateGrade()

		if grade < minVal || grade > maxVal {
			t.Fatalf("grade %f out of bounds [%f, %f]", grade, minVal, maxVal)
		}

		if grade < observedMin {
			observedMin = grade
		}
		if grade > observedMax {
			observedMax = grade
		}

		sum += grade
	}

	mean := sum / float64(samples)
	expectedMean := (minVal + maxVal) / 2.0 // 2.50

	if math.Abs(mean-expectedMean) > 0.05 {
		t.Fatalf("sample mean %f outside expected tolerance [2.45, 2.55]", mean)
	}

	if observedMin < 0.0 || observedMax > 5.0 {
		t.Fatalf("observed min/max violation: min=%f, max=%f", observedMin, observedMax)
	}
}

func TestUniformGradeGeneratorValidation(t *testing.T) {
	t.Run("min >= max rejected", func(t *testing.T) {
		_, err := NewUniformGradeGenerator(5.0, 5.0)
		if !errors.Is(err, ErrInvalidRange) {
			t.Fatalf("expected ErrInvalidRange, got: %v", err)
		}

		_, err = NewUniformGradeGenerator(5.0, 2.0)
		if !errors.Is(err, ErrInvalidRange) {
			t.Fatalf("expected ErrInvalidRange, got: %v", err)
		}
	})

	t.Run("NaN / Inf rejected", func(t *testing.T) {
		_, err := NewUniformGradeGenerator(math.NaN(), 5.0)
		if !errors.Is(err, ErrNonFinite) {
			t.Fatalf("expected ErrNonFinite, got: %v", err)
		}

		_, err = NewUniformGradeGenerator(0.0, math.Inf(1))
		if !errors.Is(err, ErrNonFinite) {
			t.Fatalf("expected ErrNonFinite, got: %v", err)
		}
	})

	t.Run("Reproducible generator with custom rand", func(t *testing.T) {
		r1 := rand.New(rand.NewPCG(42, 100))
		gen1, _ := NewUniformGradeGeneratorWithRand(0.0, 5.0, r1)

		r2 := rand.New(rand.NewPCG(42, 100))
		gen2, _ := NewUniformGradeGeneratorWithRand(0.0, 5.0, r2)

		for i := 0; i < 50; i++ {
			if gen1.GenerateGrade() != gen2.GenerateGrade() {
				t.Fatalf("mismatch in reproducible generation at iteration %d", i)
			}
		}
	})
}
