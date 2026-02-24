package detect

import "math"

func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	var res float64
	for _, count := range freq {
		p := count / length
		res -= p * math.Log2(p)
	}
	return res
}
