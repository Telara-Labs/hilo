package bundle

import (
	"crypto/sha256"
	"strings"
)

// codeWords maps one byte to one word. A verification code is six words, 48
// bits of a domain-separated digest that both screens display.
var codeWords = [256]string{
	"acid", "acorn", "actor", "adapt", "adobe", "agent", "alarm", "album", "alpha", "amber", "angle",
	"ankle", "apple", "april", "arena", "arrow", "aspen", "atlas", "attic", "audio", "autumn",
	"award", "bacon", "badge", "bagel", "baker", "bamboo", "banjo", "barn", "basil", "basin", "beach",
	"beard", "berry", "bison", "blade", "blank", "blaze", "bloom", "board", "boat", "bonus", "booth",
	"brain", "brass", "bread", "brick", "bridge", "brook", "brush", "bucket", "buddy", "bugle",
	"cabin", "cable", "cactus", "camel", "candy", "canoe", "canyon", "cargo", "carpet", "cedar",
	"chalk", "charm", "cherry", "chess", "chief", "cider", "cinema", "circle", "citrus", "clay",
	"cliff", "clock", "cloud", "clover", "coast", "cobalt", "cocoa", "comet", "coral", "cotton",
	"couch", "crane", "crayon", "creek", "crown", "crystal", "cube", "daisy", "dance", "delta",
	"denim", "desert", "diary", "dinner", "dolphin", "donkey", "dragon", "dream", "drift", "drum",
	"eagle", "earth", "easel", "echo", "eclipse", "elbow", "ember", "engine", "equal", "fabric",
	"falcon", "feather", "fence", "fern", "ferry", "fiber", "field", "flame", "flute", "forest",
	"fossil", "fox", "frost", "fruit", "galaxy", "garden", "garlic", "gecko", "giant", "ginger",
	"glacier", "globe", "glove", "goat", "grain", "granite", "grape", "gravel", "guitar", "hammer",
	"harbor", "hazel", "helmet", "heron", "hollow", "honey", "horizon", "iceberg", "igloo", "indigo",
	"island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jewel", "jungle", "kayak", "kernel",
	"kettle", "kiwi", "koala", "ladder", "lagoon", "lantern", "laser", "lava", "lemon", "lily",
	"linen", "lizard", "lobster", "lotus", "magnet", "mango", "maple", "marble", "meadow", "melon",
	"meteor", "mint", "mirror", "mitten", "moose", "mosaic", "motor", "mountain", "mural", "nectar",
	"needle", "nickel", "noodle", "north", "nutmeg", "oasis", "ocean", "olive", "onion", "orbit",
	"orchid", "otter", "oyster", "paddle", "palm", "panda", "paper", "parrot", "pasta", "peach",
	"pebble", "pepper", "piano", "pillow", "pine", "planet", "plum", "pocket", "polar", "pony",
	"poppy", "prism", "pumpkin", "puzzle", "quartz", "quilt", "rabbit", "radar", "radio", "raven",
	"reef", "ribbon", "river", "robin", "rocket", "saddle", "salmon", "sandal", "satin", "scarf",
	"shadow", "shell", "silver", "sketch", "sloth", "snow", "socket", "spark", "spider", "spruce",
	"squid", "stone", "sugar",
}

// Code returns the six-word verification code binding every given value.
func Code(domain string, values ...string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, v := range values {
		h.Write([]byte{0})
		h.Write([]byte(v))
	}
	sum := h.Sum(nil)
	out := make([]string, 6)
	for i := range out {
		out[i] = codeWords[sum[i]]
	}
	return strings.Join(out, " ")
}
