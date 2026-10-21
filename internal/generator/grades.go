package generator

import (
	"errors"
	"math"
	"math/rand/v2"
)

var (
	ErrInvalidRange = errors.New("min must be strictly less than max")
	ErrNonFinite    = errors.New("range values must be finite numbers")
)

type GradeGenerator interface {
	GenerateGrade() float64
}

type UniformGradeGenerator struct {
	min float64
	max float64
	r   *rand.Rand
}

func NewUniformGradeGenerator(min, max float64) (*UniformGradeGenerator, error) {
	if math.IsNaN(min) || math.IsNaN(max) || math.IsInf(min, 0) || math.IsInf(max, 0) {
		return nil, ErrNonFinite
	}
	if min >= max {
		return nil, ErrInvalidRange
	}
	return &UniformGradeGenerator{
		min: min,
		max: max,
	}, nil
}

func NewUniformGradeGeneratorWithRand(min, max float64, r *rand.Rand) (*UniformGradeGenerator, error) {
	gen, err := NewUniformGradeGenerator(min, max)
	if err != nil {
		return nil, err
	}
	gen.r = r
	return gen, nil
}

func (g *UniformGradeGenerator) GenerateGrade() float64 {
	var f float64
	if g.r != nil {
		f = g.r.Float64()
	} else {
		f = rand.Float64()
	}

	val := g.min + f*(g.max-g.min)
	rounded := math.Round(val*100.0) / 100.0

	if rounded < g.min {
		return g.min
	}
	if rounded > g.max {
		return g.max
	}
	return rounded
}
