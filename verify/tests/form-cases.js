// Look-alike payload pairs shared by the rule tests and the recovery
// drills. Each pair is visually near-identical but differs in character
// form — and therefore in its actual UTF-8 bytes. Under the byte-exact
// sealing rule the two forms are distinct identities: retransmitting one
// form under the other form's batch id must conflict, never return the
// original receipt.
//
// The character forms are written as explicit escapes: the differences are
// invisible in source and must not be "helpfully" normalized by an editor.

export const FORM_CASES = [
  {
    name: "full-width vs half-width letters",
    // ＡＢＣ１２３ vs ABC123
    original: "\uFF21\uFF22\uFF23\uFF11\uFF12\uFF13",
    altered: "ABC123",
  },
  {
    name: "combining vs precomposed accents",
    // e + combining acute vs precomposed é
    original: "cafe\u0301",
    altered: "caf\u00E9",
  },
  {
    name: "Windows vs Unix newlines",
    original: "line1\r\nline2",
    altered: "line1\nline2",
  },
  {
    name: "trailing whitespace",
    original: "sail trim \t",
    altered: "sail trim",
  },
];
