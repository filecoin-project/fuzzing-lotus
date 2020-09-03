// Differential fuzzing to check whether any inaccuracies can be introduced by using fixed width arithmetic
// It's not going to overflow, but could it lose accuracy?
// Ans: no, not a problem with the current MaxIndex
// Some private fields copied from go-amt-ipld/amt.go 6263827e49

package fuzz

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"

	"github.com/google/gofuzz/bytesource"
)

// from go-amt-ipld/amt.go:18 6263827e49
const width = 8

// created once to avoid reAllocating every execution
var bigWidth = big.NewInt(8)

//var bigMaxUint64 = big.NewInt(math.MaxUint64)

// what is the max height?
// width ^ maxHeight == MaxIndex (+-1?)
// 8 ^ 16 == (1 << 48)
// index [0..maxIndex)
// Height starts at 0, so we use maxHeight + 1 == 16
const maxHeight = 15

// from go-amt-ipld/amt.go:461 6263827e49
func nodesForHeight(width, height int) uint64 {
	val := math.Pow(float64(width), float64(height))
	if val >= float64(math.MaxUint64) {
		//log.Errorf("nodesForHeight overflow! This should never happen, please report this if you see this log message")
		// panic here instead for fuzzing purposes?
		return math.MaxUint64
	}

	return uint64(val)
}

// implementation avoiding limited-accuracy float64
func bigNodesForHeight(width, height *big.Int) uint64 {
	bigVal := big.NewInt(0)
	bigVal.Exp(width, height, nil)
	// bigVal >= math.MaxUint64
	// could also use bigVal.IsUint64
	//if bigVal.Cmp(bigMaxUint64) >= 0 {
	//	//log.Errorf("nodesForHeight overflow! This should never happen, please report this if you see this log message")
	//	// panic here instead for fuzzing purposes?
	//	return math.MaxUint64
	//}
	if !bigVal.IsUint64() {
		// Do the check to ensure Uint64() result is not undefined
		//panic("Bug in harness, shouldn't be possible")
		return math.MaxUint64
	}

	return bigVal.Uint64()
}

// TODO also check when modifying width, even though this is a const?
// currently search space is small enought that you might as well just test all possibilities
func FuzzNodesForHeight(data []byte) int {
	// because we only want a single int within our range, we just use rand
	// rather than the full gofuzz `Fuzzer`
	// could also just use mod, but I like this more :)
	r := rand.New(bytesource.New(data))
	height := r.Intn(maxHeight + 2) // should only be +1 but check for breathing room
	bigHeight := big.NewInt(int64(height))
	result1 := nodesForHeight(width, height)
	result2 := bigNodesForHeight(bigWidth, bigHeight)

	if result1 != result2 {
		fmt.Printf("Input: width=%d, height=%d", width, height)
		fmt.Printf("Result1=%d", result1)
		fmt.Printf("Result2=%d", result2)
		panic("Not Equal!")
	}
	return 0
}
