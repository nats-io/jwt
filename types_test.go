package jwt

import "testing"

func TestTagList(t *testing.T) {
	tags := TagList{}

	tags.Add("one")

	AssertEquals(true, tags.Contains("one"), t)
	AssertEquals(true, tags.Contains("ONE"), t)
	AssertEquals("one", tags[0], t)

	tags.Add("TWO")

	AssertEquals(true, tags.Contains("two"), t)
	AssertEquals(true, tags.Contains("TWO"), t)
	AssertEquals("two", tags[1], t)

	tags.Remove("ONE")
	AssertEquals("two", tags[0], t)
	AssertEquals(false, tags.Contains("one"), t)
	AssertEquals(false, tags.Contains("ONE"), t)
}

func TestStringList(t *testing.T) {
	slist := StringList{}

	slist.Add("one")

	AssertEquals(true, slist.Contains("one"), t)
	AssertEquals(false, slist.Contains("ONE"), t)
	AssertEquals("one", slist[0], t)

	slist.Add("TWO")

	AssertEquals(false, slist.Contains("two"), t)
	AssertEquals(true, slist.Contains("TWO"), t)
	AssertEquals("TWO", slist[1], t)

	slist.Remove("ONE")
	AssertEquals("one", slist[0], t)
	AssertEquals(true, slist.Contains("one"), t)
	AssertEquals(false, slist.Contains("ONE"), t)

	slist.Add("ONE")
	AssertEquals(true, slist.Contains("one"), t)
	AssertEquals(true, slist.Contains("ONE"), t)
	AssertEquals(3, len(slist), t)

	slist.Remove("one")
	AssertEquals("TWO", slist[0], t)
	AssertEquals(false, slist.Contains("one"), t)
	AssertEquals(true, slist.Contains("ONE"), t)
}
