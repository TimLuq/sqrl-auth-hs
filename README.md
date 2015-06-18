# SQRL
SQRL is a cryptographic authentication system to be used instead of a common password login. It supports cross-device login as well as same-device login.

# sqrl-auth-hs
This package is primarily for server implementations. This provides support for the protocol and common usage. It is also possible to add unofficial extensions the protocol by use of the following functions:
``` haskell
clientPostData :: ByteString -> SQRLClientPost a -> Maybe ByteString
serverPlainData :: Text -> SQRLServerData a -> Maybe Text
```

## Future
When this package gets to be somewhat stable a specialiced package for Yesod (and perhaps other frameworks) should be developed. The development could be by me or by somone who knows more about the authentication systems for the framework(s) in question.
