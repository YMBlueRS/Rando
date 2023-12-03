function test
{
  $a = "Language Mode:"
  $a
  $ExecutionContext.SessionState.LanguageMode
}

test > $home\Output\LM.out
