package ntlm

import (
	"fmt"
	"io"
	"testing"
)

type ntlmTest struct {
	out, in string
}

var golden = []ntlmTest{
	{"31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"186cb09181e2c2ecaac768c47c729904", "a"},
	{"79312f7ee81e59d4e76a15021e74b597", "ab"},
	{"e0fba38268d0ec66ef1cb452d5885e53", "abc"},
	{"eb4ff39b74b0cbce20a4f62dbd1e3585", "abcd"},
	{"3f5156e39d9c989c2609fd8329a46ca4", "abcde"},
	{"b5fe2db507cc5ac540493d48fbd5fe33", "abcdef"},
	{"352dfe551d62459b20349b78a21a2f37", "abcdefg"},
	{"2141636b734704847575e3731fa1f2c4", "abcdefgh"},
	{"e18614f7c6811f043fbf54205e929052", "abcdefghi"},
	{"03af89fddda475eda5ee9496aa1d396b", "abcdefghij"},
	{"a6179e04a3929ca0d2270252b3e28718", "Discard medicine more than two years old."},
	{"efcc440c175c94ac9a2787d52aef7761", "He who has a shady past knows that nice guys finish last."},
	{"3fb748906f7e6976e6c57f9194009486", "I wouldn't marry him with a ten foot pole."},
	{"01f1284ebf3daa9bde963128d29e1a82", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
	{"eed3b3230716bd064c8556caede5318b", "The days of the digital watch are numbered.  -Tom Stoppard"},
	{"5c4651d2210c2f1efcdad4f68332e367", "Nepal premier won't resign."},
	{"db017ced5bd3a4b24fa73eb5b7f0476e", "For every action there is an equal and opposite government program."},
	{"6597cdc776287377fe8d206eda135438", "His money is twice tainted: 'taint yours and 'taint mine."},
	{"e48701a44f116d0609d5930884f81962", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
	{"91e312a6b25a16bd51838b7529754dc6", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
	{"450b3a9da5475d6e2ce4d2012f57faf6", "size:  a.out:  bad magic"},
	{"b7443043b61a6cf551da8c6342680561", "The major problem is with sendmail.  -Mark Horton"},
	{"ca6bb24613e613aedd9a49f0b8a0a2f3", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
	{"f1a0bf4600060c30824cc2ce15403090", "If the enemy is within range, then so are you."},
	{"98c4e1a81d26afe01bb3ef2a7a223a0b", "It's well we cannot hear the screams/That we create in others' dreams."},
	{"b4b5ab3e4282a36cd3aff3f42d7509c3", "You remind me of a TV show, but that's all right: I watch it anyway."},
	{"d7de3b8145b5ae0a8cc100735e3902f8", "C is as portable as Stonehedge!!"},
	{"561b28dfa8ff8e6b96afd3cc9aa78339", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
	{"39ed435fbd63b45ab92a5a67f2a0fc73", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
	{"c8b2dea739380a365390d745ccca8d05", "How can you write a big system without C++?  -Paul Glick"},
}

// Based on the crypto/md4 test suite.
func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		c := New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("ntlm[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestSizes(t *testing.T) {
	c := New()
	if size := c.Size(); size != Size {
		t.Fatalf("Size() = %d, want %d", size, Size)
	}
	if blockSize := c.BlockSize(); blockSize != BlockSize {
		t.Fatalf("BlockSize() = %d, want %d", blockSize, BlockSize)
	}
}
