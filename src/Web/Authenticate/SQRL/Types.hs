{-# LANGUAGE OverloadedStrings #-}
module Web.Authenticate.SQRL.Types where

import Data.String
import Data.Word
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Binary
import Data.Byteable
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Put as BP
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Base64.URL.Lazy as B64UL
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Bits
import qualified Data.Foldable
import Data.Maybe (fromMaybe, mapMaybe)
import Data.List (nubBy, sortBy, intersperse)
import Data.Char (toLower)

import Numeric
import Data.Text.Read


import Control.Applicative
import Control.Arrow (first)


-- | Decodes Base64URL encoded data regardless of padding.
dec64unpad :: ByteString -> Either String ByteString
dec64unpad x =
  let xd = BS.length x `mod` 4
      x' = if xd == 0 then B64U.decode x else LBS.toStrict <$> B64UL.decode (LBS.fromChunks [x, BS.replicate (4 - xd) eq])
      eq = fromIntegral (fromEnum '=') :: Word8
  in x'

-- | Encodes data to Base64URL encoded data without padding.
enc64unpad :: ByteString -> ByteString
enc64unpad = fst . BS.spanEnd (==eq) . B64U.encode
  where eq = fromIntegral (fromEnum '=') :: Word8

newtype IPBytes = IPBytes Word32 deriving (Show, Eq)
type UnixTime = Word32
type Counter = Word32
type RandomInt = Word32
newtype UnlockKey = UnlockKey { publicUnlockKey :: ByteString } deriving (Show, Eq)
newtype IdentityKey = IdentityKey { publicIdentityKey :: ByteString } deriving (Show, Eq)
newtype ServerUnlockKey = ServerUnlockKey { publicServerUnlockKey :: ByteString } deriving (Show, Eq)
newtype VerifyUnlockKey = VerifyUnlockKey { publicVerifyUnlockKey :: ByteString } deriving (Show, Eq)

newtype IdentitySignature = IdentitySignature { identitySignature :: ByteString } deriving (Show, Eq)
newtype UnlockSignature   = UnlockSignature   { unlockSignature   :: ByteString } deriving (Show, Eq)



class Signature s where
  signature :: s -> ByteString
  mkSignature :: ByteString -> s


instance Signature IdentitySignature where
  signature = identitySignature
  mkSignature = IdentitySignature
instance Signature UnlockSignature where
  signature = unlockSignature
  mkSignature = UnlockSignature

class PublicKey k where
  publicKey :: k -> ByteString
  mkPublicKey :: ByteString -> k

instance PublicKey UnlockKey where
  publicKey = publicUnlockKey
  mkPublicKey = UnlockKey
instance PublicKey IdentityKey where
  publicKey = publicIdentityKey
  mkPublicKey = IdentityKey
instance PublicKey ServerUnlockKey where
  publicKey = publicServerUnlockKey
  mkPublicKey = ServerUnlockKey
instance PublicKey VerifyUnlockKey where
  publicKey = publicVerifyUnlockKey
  mkPublicKey = VerifyUnlockKey



data SQRLClientPost a
  = SQRLClientPost
    { sqrlServerData    :: Either SQRLUrl (SQRLServerData a)
    , sqrlClientData    :: SQRLClientData
    , sqrlSignatures    :: SQRLSignatures
    , sqrlPostAll       :: [(ByteString, ByteString)]           -- ^ This must be keept up to date with the actual contents, else the 'sqrlClientPostBytes' will not reflect any changes.
    }
  deriving (Show)

{- There migt be no need for this...
modifySQRLServerData :: (SQRLServerData a -> SQRLServerData a) -> SQRLClientPost a -> SQRLClientPost a
modifySQRLServerData f x@SQRLClientPost { sqrlServerData = xx, sqrlPostAll = yy } = let r = f xx in x { sqrlServerData = r, sqrlPostAll = ("server", serverToBytes r) : yy }
  where serverToBytes = "" -- TO DO
-}

-- | Modify the signatures of a 'SQRLClientPost'.
modifySQRLSignatures :: (SQRLSignatures -> SQRLSignatures) -> SQRLClientPost a -> SQRLClientPost a
modifySQRLSignatures f x@SQRLClientPost { sqrlSignatures = xx, sqrlPostAll = yy } = let r = f xx in x { sqrlSignatures = r, sqrlPostAll = sigsToBytes r ++ filter (flip notElem ["ids","pids","urs"] . fst) yy }
  where sigsToBytes SQRLSignatures
          { signIdentity        = csig
          , signPreviousID      = psig
          , signUnlock          = usig
          } = (:) ("ids",  enc64unpad $ signature csig)
              $ ms (((,) "pids" . enc64unpad . signature) <$> psig)
              $ ms (((,) "urs"  . enc64unpad . signature) <$> usig)
              []
        ms (Just q) = (:) q
        ms Nothing  = id

modifySQRLClientData :: (SQRLClientData -> SQRLClientData) -> SQRLClientPost a -> SQRLClientPost a
modifySQRLClientData f x@SQRLClientPost { sqrlClientData = xx, sqrlPostAll = yy } = let r = f xx in x { sqrlClientData = r, sqrlPostAll = ("client", clientToBytes r) : filter ((/=) "client" . fst) yy }
  where clientToBytes SQRLClientData
          { clientVersion       = ver
          , clientCommand       = act
          , clientOptions       = opt
          , clientAskResponse   = akr
          , clientRefererURL    = url
          , clientIdentity      = cid
          , clientPreviousID    = pid
          , clientServerUnlock  = suk
          , clientVerifyUnlock  = vuk
          } = enc64unpad $ BS.concat
              [ "ver=", toBytes ver, "\r\n"
              , "cmd=", fromString (map toLower $ show act), "\r\n"
              , ms ((flip BS.append "\r\n" . BS.append "opt=" . BS.intercalate "~" . map (fromString . show)) <$> opt)
              , ms ((flip BS.append "\r\n" . BS.append "btn=" . fromString . show . fromEnum) <$> akr)
              , ms ((flip BS.append "\r\n" . BS.append "url=" . enc64unpad . TE.encodeUtf8) <$> url)
              , "idk=", enc64unpad (publicKey cid), "\r\n"
              , ms ((flip BS.append "\r\n" . BS.append "pidk=" . enc64unpad . publicKey) <$> pid)
              , ms ((flip BS.append "\r\n" . BS.append "suk="  . enc64unpad . publicKey) <$> suk)
              , ms ((flip BS.append "\r\n" . BS.append "vuk="  . enc64unpad . publicKey) <$> vuk)
              ]
        ms = fromMaybe ""

{-
modifySQRLServerData :: (SQRLServerData a -> SQRLServerData a) -> SQRLClientPost a -> SQRLClientPost a
modifySQRLServerData f x@SQRLClientPost { sqrlClientData = xx, sqrlPostAll = yy } = let r = f xx in x { sqrlClientData = r, sqrlPostAll = ("client", clientToBytes r) : yy }
  where clientToBytes SQRLServerData
          { serverVersion       = ver
          , serverNut           = nut
          , serverTransFlags    = tif
          , serverQueryPath     = qry
          , serverFriendlyName  = sfn
          , serverUnlockKey     = suk
          , serverAsk           = ask
          , serverURL           = url
          , serverPlainExtra    = xtr
          } = enc64unpad $ BS.concat
              [ "ver=", toBytes ver, "\r\n"
              , "nut=", enc64unpad $ case nut of { Left z -> TE.encodeUtf8 z ; Right z -> encode z}, "\r\n"
              , "tif=", show tif, "\r\n"
              , "qry=", TE.encodeUtf8 qry, "\r\n"
              , "sfn=", TE.encodeUtf8 sfn, "\r\n"
              , ms ((flip BS.append "\r\n" . BS.append "suk="  . enc64unpad . publicKey) <$> suk)
              , ms ((flip BS.append "\r\n" . BS.append "ask="  . enc64unpad . publicKey) <$> ask)
              ]
        ms = fromMaybe ""
-}

sqrlClientPostBytes :: Binary a => SQRLClientPost a -> (SQRLClientPost a, LBS.ByteString)
sqrlClientPostBytes p@SQRLClientPost { sqrlPostAll = pall } =
  (p { sqrlPostAll = orderedPost }, LBS.concat $ intersperse "&" $ map (\(a, b) -> LBS.fromChunks [a, "=", fst (BS.spanEnd (== fromIntegral (fromEnum '=')) b)]) orderedPost)
  where orderedPost = nubBy (\(a, _) (b, _) -> a == b) $ sortBy orderWith pall
        orderWith (a, _) (b, _)
          | a == b = EQ
          | a == "client" = LT
          | b == "client" = GT
          | a == "server" = LT
          | b == "server" = GT
          | a == "ids"    = LT
          | b == "ids"    = GT
          | otherwise = compare a b

clientPostData :: Binary a => ByteString -> SQRLClientPost a -> Maybe ByteString
clientPostData k = lookup k . sqrlPostAll

type Nounce = ByteString

instance Binary IPBytes where
  get = IPBytes <$> get
  put (IPBytes x) = put x

class IPRepresentation a where
  fromIP :: a -> IPBytes

fromIPv4 :: (Word8, Word8, Word8, Word8) -> IPBytes
fromIPv4 (a,b,c,d) = IPBytes $ (fromIntegral a `shiftL` 24) .|. (fromIntegral b `shiftL` 16) .|. (fromIntegral c `shiftL` 8) .|. fromIntegral d
instance IPRepresentation Word32 where
  fromIP = IPBytes

-- | An invalid IP. Use when connection may have been intercepted (when TLS is not used).
noIP :: IPBytes
noIP = IPBytes 0




readKey :: PublicKey k => String -> Text -> k
readKey fn t = case dec64unpad $ encodeASCII (fn ++ ": readKey") t of
  Left err -> error $ fn ++ ": readKey: " ++ err
  Right t' -> mkPublicKey t'

readSignature :: Signature s => String -> Text -> s
readSignature fn = mkSignature . publicUnlockKey . readKey (fn ++ ": readSignature")

readNounce :: String -> Text -> Nounce
readNounce fn = publicUnlockKey . readKey (fn ++ ": readNounce")



-- | A SQRL Nut without any bound data.
type SQRLNut = SQRLNutEx ()

-- | A SQRL Nut which may have some data bound to it.
data SQRLNutEx a
  = SQRLNut
    { nutIP      :: IPBytes              -- ^ The IP (or 32 bits of it). This should be used when TLS is in use.
    , nutTime    :: UnixTime             -- ^ The time at which this nut was created.
    , nutCounter :: Counter              -- ^ The SQRL counter value when this nut was created.
    , nutRandom  :: RandomInt            -- ^ Some random data generated when the nut was created.
    , nutQR      :: Bool                 -- ^ True if this nut is being used for cross-device login.
    , nutExtra   :: Maybe a              -- ^ Optionally something that is bound to this nut. This may be a session id or username when verifying a user action through the use of ASK.
    }
  | SQRLNutEncrypted 
    { encNutIV     :: ByteString         -- ^ The IV t be used during decryption.
    , encNutKey    :: ByteString         -- ^ The key to use for decryption.
    , encNutVer    :: ByteString         -- ^ The signature to detect tampering.
    , encNutData   :: ByteString         -- ^ The actual nut.
    , encNutExtra  :: ByteString         -- ^ Any extra encrypted data.
    , encNutNounce :: ByteString         -- ^ The random nounce which is part of the IV.
    }
  deriving (Eq, Show)


instance Binary a => Binary (SQRLNutEx a) where
  put = putSQRLNut
  get = getSQRLNut

-- | Specialiced version of 'put'.
putSQRLNut :: Binary a => SQRLNutEx a -> Put
putSQRLNut (SQRLNut { nutIP = ip, nutTime = ut, nutCounter = cn, nutRandom = ri, nutQR = bl, nutExtra = ex }) =
  put ip  <* putWord32 ut <* putWord32 cn
  <* putWord32 ((.|.) (ri .&. 0xFFFFFFFB) $ (case ex of { Nothing -> 2 ; _ -> 0 }) .|. (if bl then 1 else 0))
  <* Data.Foldable.forM_ ex put
putSQRLNut (SQRLNutEncrypted {}) = fail "putSQRLNut: An encrypted nut may not be 'Put'."

-- | Specialiced version of 'get'.
getSQRLNut :: Binary a => Get (SQRLNutEx a)
getSQRLNut = do
  (ip, ut, en, ri) <- (,,,) <$> get <*> getWord32 <*> getWord32 <*> getWord32
  ex <- if ri .&. 2 == 0 then return Nothing else Just <$> get
  return SQRLNut { nutIP = ip, nutTime = ut, nutCounter = en, nutRandom = ri .&. 0xFFFFFFFB, nutQR = ri .&. 1 /= 0, nutExtra = ex }

-- | A command issued by the SQRL Client.
data SQRLCommandAction = QUERY | IDENT | DISABLE | ENABLE | REMOVE | CMD Text deriving (Show, Eq)

instance IsString SQRLCommandAction where
  fromString = readCommand . T.pack

-- | Reads a single command.
readCommand :: Text -> SQRLCommandAction
readCommand "query"   = QUERY
readCommand "ident"   = IDENT
readCommand "disable" = DISABLE
readCommand "enable"  = ENABLE
readCommand "remove"  = REMOVE
readCommand x         = CMD x

type Domain = Text
type Path = Text
type Realm = Text
type Origin = Text



-- | Structured parts that make up a SQRL URL.
data SQRLUrl
  = SQRLUrl
    { sqrlUrlSecure    :: Bool
    , sqrlUrlDomain    :: Domain
    , sqrlUrlRealm     :: Realm
    , sqrlUrlPath      :: Path
    , sqrlUrlQuery     :: Text
    }
  deriving (Eq)

-- | So it's simple to use with @-XOverloadedStrings@.
instance IsString SQRLUrl where
  fromString = fromEither . readSQRLUrl . T.pack
    where fromEither (Right x) = x
          fromEither (Left er) = error er

instance Show SQRLUrl where
  show = show . T.unpack . sqrlUrl
instance Read SQRLUrl where
  readsPrec i s = mapMaybe f (readsPrec i s :: [(String, String)])
    where f (x, y) = case readSQRLUrl (T.pack x) of
            Left  _ -> Nothing
            Right u -> Just (u, y)

-- | Turn a 'SQRLUrl' into normal 'Text'.
sqrlUrl :: SQRLUrl -> Text
sqrlUrl (SQRLUrl sec dom rlm pth qry) =
  T.concat ( (if sec then "sqrl://" else "qrl://")
           : dom : "/"
           : (if T.null rlm then id else (\x -> rlm : "|" : x))
           [ pth, "?", qry]
           )

sqrlUrlToBS :: SQRLUrl -> ByteString
sqrlUrlToBS = TE.encodeUtf8 . sqrlUrl

-- | Return the origin, @\url -> Text.append (sqrlUrlDomain url) (sqrlUrlRealm url)@.
sqrlUrlOrigin :: SQRLUrl -> Origin
sqrlUrlOrigin (SQRLUrl { sqrlUrlDomain = dom, sqrlUrlRealm = rlm }) =
  T.append dom rlm

-- | Reads a 'Text' as a 'SQRLUrl'.
readSQRLUrl :: Text -> Either String SQRLUrl
readSQRLUrl t
  | T.take 6 t == "qrl://"  = readUrl_0 False $ T.drop 6 t
  | T.take 7 t == "sqrl://" = readUrl_0 True  $ T.drop 7 t
  | otherwise = Left "readSQRLUrl: Invalid scheme."
  where readUrl_0 sec t' =
          let (drp, qry) = T.break ('?'==) t'
              (dom, rap) = T.break (`elem` "/|") drp
              (rlm, pth) = let (r', p') = T.break ('|'==) $ T.tail rap in if T.null p' then (p', r') else (r', T.tail p')
          in if T.null dom then Left "readSQRLUrl: No domain." else if T.null qry then Left "readSQRLUrl: No querystring." else Right SQRLUrl
             { sqrlUrlSecure = sec
             , sqrlUrlDomain = dom
             , sqrlUrlRealm  = rlm
             , sqrlUrlPath   = pth
             , sqrlUrlQuery  = T.tail qry
             }



newtype AskResponse = AskResponse Int deriving (Eq, Ord, Show)
instance Bounded AskResponse where
  minBound = AskResponse 0
  maxBound = AskResponse 2
instance Enum AskResponse where
  fromEnum (AskResponse a) = a
  toEnum = AskResponse
instance Read AskResponse where
  readsPrec p x = case take 12 x of
    "AskResponse " -> map (first AskResponse) (readsPrec p (drop 12 x))
    _ -> map (first AskResponse) (readsPrec p x)
-- Reads the response of an ask. According to the spec (as of 2015-06-17) the text is not base64 encoded, just plain utf-8.
-- Text removed 2015-07
-- | The response of an ask, that is which button the user has pressed.
--
-- The zeroth button is the unnamed default choice and may, depending on the server, be the same as one of the buttons.
askResponse :: Int -> AskResponse
askResponse = AskResponse


-- | Get the index of the default button for an agreed 'SQRLVersion'.
askResponseButtonDefault :: VersionNum -> Int
askResponseButtonDefault = const 3

data SQRLClientOption = SQRLONLY | HARDLOCK | OPT Text deriving (Eq, Show)
type SQRLClientOptions = [SQRLClientOption]

instance IsString SQRLClientOption where
  fromString = clientOption . T.pack

-- | Creates a 'SQRLClientOption' from a 'Text'.
clientOption :: Text -> SQRLClientOption
clientOption x
  | x == "sqrlonly" = SQRLONLY
  | x == "hardlock" = HARDLOCK
  | otherwise       = OPT x

-- | Reads a list of none, one, or multiple 'SQRLClientOption'.
readClientOptions :: Text -> SQRLClientOptions
readClientOptions = map clientOption . filter (not . T.null) . T.split ('~'==)




-- | A structure representing the @client@ parameter sent by the SQRL client.
data SQRLClientData
  = SQRLClientData
    { clientVersion       :: SQRLVersion                -- ^ The client version support.
    , clientCommand       :: SQRLCommandAction          -- ^ The command the client want to execute.
    , clientOptions       :: Maybe SQRLClientOptions    -- ^ The options requested by the client.
    , clientAskResponse   :: Maybe AskResponse          -- ^ Any response to a message or confirmation that needed to be shown to the user.
    , clientRefererURL    :: Maybe Text                 -- ^ The client will include a “url=” parameter in the initial “query” command of any identity authentication initiated by the SQRL client's receipt of a web browser's HTML query on port 25519 of the localhost IP 127.0.0.1 when that HTML query contains a “Referer:” header and no “Origin:” header.
    , clientIdentity      :: IdentityKey                -- ^ The current identity of the user.
    , clientPreviousID    :: Maybe IdentityKey          -- ^ The previous identity of the user if the identity has been changed.
    , clientServerUnlock  :: Maybe ServerUnlockKey      -- ^ The key used to unlock the users identity.
    , clientVerifyUnlock  :: Maybe VerifyUnlockKey      -- ^ The key used to verify an unlock action.
    }
  deriving (Show)

-- | A structure representing the @ids@ parameter sent from a SQRL client.
data SQRLSignatures
  = SQRLSignatures
    { signIdentity        :: IdentitySignature          -- ^ A signature by the users current identity.
    , signPreviousID      :: Maybe IdentitySignature    -- ^ A signature signed by the users previous identity.
    , signUnlock          :: Maybe UnlockSignature      -- ^ A signtaure to verify an unlock action.
    }
  deriving (Show)

-- | A user may be asked to fill in a value and may use one out of two buttons (or OK by default) to send back the response.
data SQRLAsk
  = SQRLAsk
    { askMessage   :: Text         -- ^ The message to be shown to the user.
--    , askInput     :: Bool         -- ^ If the user is expected to input a response message (such as a new username).
    , askButtons   :: [AskButton]  -- ^ A list of buttons.
    }
    deriving (Show)

-- | Reads a Base64 encoded version of the @ask=@ server option.
readASK :: Text -> SQRLAsk
readASK t = case map (toRight (error . (++) "readASK: utf8 error: " . show) . TE.decodeUtf8' . toRight (error . (++) "readASK: ") . dec64unpad . encodeASCII "readASK") $ T.split ('~'==) t of
             []    -> SQRLAsk "" []
             [x]   -> SQRLAsk x []
             (x:r) -> SQRLAsk x $ map readAskButton r
  where readAskButton x = let (t', u) = T.break (';'==) x in if T.null u then (t', Nothing) else (t', Just $ T.tail u)
        toRight :: (a -> b) -> Either a b -> b
        toRight f x = case x of
          Left xl -> f xl
          Right y -> y

type AskButton = (Text, Maybe Text)

type VersionNum = Int

data SQRLVersion
  = VersionList     [SQRLVersion]
  | VersionNum      VersionNum
  | VersionInterval VersionNum VersionNum
  deriving (Show, Eq)

instance Byteable SQRLVersion where
  toBytes (VersionList l) = BS.intercalate "," (map toBytes l)
  toBytes (VersionNum n) = fromString (show n)
  toBytes (VersionInterval n0 n1) = fromString (show n0 ++ "-" ++ show n1)

sqrlVersion1 :: SQRLVersion
sqrlVersion1 = VersionNum 1

-- | Extracts the highest version contained within two version specifications.
versionCompatible :: SQRLVersion -> SQRLVersion -> Maybe VersionNum
versionCompatible (VersionNum x) (VersionNum y) = if x == y then Just x else Nothing
versionCompatible (VersionInterval xl xh) (VersionNum y) = if xl <= y && xh >= y then Just y else Nothing
versionCompatible (VersionInterval xl xh) (VersionInterval yl yh) = if xl <= yh && xh >= yl then Just (if yh < xh then yh else xh) else Nothing
versionCompatible (VersionList xs) y = let l = mapMaybe (versionCompatible y) xs in if null l then Nothing else Just $ maximum l
versionCompatible x y = versionCompatible y x

-- | A button with a specific label.
askButton :: Text -> AskButton
askButton = flip (,) Nothing

-- | A button with a label which opens a URL for the user.
askButtonUrl :: Text -> Text -> AskButton
askButtonUrl t = (,) t . Just




-- | Takes a 'ByteString' (most likely from the @client@ parameter sent by the SQRL client) and returns a structure or an error message.
readSQRLClientData :: ByteString -> Either String SQRLClientData
readSQRLClientData t = case tf <$> dec64unpad t of
  Left errmsg -> Left $ "readSQRLClientData: " ++ errmsg
  Right f -> case readVersion <$> f "ver" of
    Nothing  -> Left "readSQRLClientData: missing ver"
    Just ver -> case readCommand <$> f "cmd" of
      Nothing  -> Left "readSQRLClientData: missing cmd"
      Just cmd -> case readKey "readSQRLClientData(idk)" <$> f "idk" of
        Nothing  -> Left "readSQRLClientData: missing idk"
        Just idk -> Right SQRLClientData
          { clientVersion      = ver
          , clientCommand      = cmd
          , clientOptions      = readClientOptions <$> f "opt"
          , clientAskResponse  = (askResponse . read . T.unpack) <$> f "btn"
          , clientRefererURL   = f "url"
          , clientIdentity     = idk
          , clientPreviousID   = readKey "readSQRLClientData(pidk)" <$> f "pidk"
          , clientServerUnlock = readKey "readSQRLClientData(suk)" <$> f "suk"
          , clientVerifyUnlock = readKey "readSQRLClientData(vuk)" <$> f "vuk"
          }
  where tf dec = let t' = map (\x -> let (l', r') = T.break ('=' ==) x in (l', T.tail r')) $ filter (not . T.null) $ T.splitOn "\r\n" $
                          case TE.decodeUtf8' dec of
                           Left e -> error $ "readSQRLClientData: utf8 decoding error: " ++ show e ++ "\n      while decoding: " ++ show dec
                           Right e -> e
                 in flip lookup t'

-- | Reads the supported version(s) of a client or server.
readVersion :: Text -> SQRLVersion
readVersion t = case T.split (','==) t of
  [x] -> readVersion' x
  xs  -> VersionList $ map readVersion' xs
  where readVersion' = VersionNum . read . T.unpack

-- | Takes a 'ByteString' (most likely from the @ids=@ parameter sent by the SQRL client) and return a structure or an error message.
readSQRLSignatures :: ByteString -> Either String SQRLSignatures
readSQRLSignatures t = case tf <$> dec64unpad t of
  Left errmsg -> Left $ "readSQRLSignatures: " ++ errmsg
  Right f -> case readSignature "readSQRLSignatures(ids)" <$> f "ids" of
    Nothing  -> Left "readSQRLSignatures: missing ids"
    Just ids -> Right SQRLSignatures
      { signIdentity       = ids
      , signPreviousID     = readSignature "readSQRLSignatures(pids)" <$> f "pids"
      , signUnlock         = readSignature "readSQRLSignatures(urs)"  <$> f "urs"
      }
  where tf dec = let t' = map (\x -> let (l', r') = T.break ('=' ==) x in (l', T.tail r')) $ filter (not . T.null) $ T.splitOn "\r\n" $
                          case TE.decodeUtf8' dec of
                           Left e -> error $ "readSQRLSignatures: utf8 decoding failed: " ++ show e ++ "\n    while decoding: " ++ show dec
                           Right r -> r
                 in flip lookup t'


-- | A collection of flags conveying information about execution state of a command.
newtype TransactionInformationFlags = TIF Int deriving (Eq, Read)

instance Bits TransactionInformationFlags where
  (TIF a) .&. (TIF b) = TIF $ a .&. b
  (TIF a) .|. (TIF b) = TIF $ a .|. b
  xor (TIF a) (TIF b) = TIF $ xor a b
  complement (TIF a) = TIF $ complement a
  shift (TIF a)   = TIF . shift a
  shiftL (TIF a)  = TIF . shiftL a
  shiftR (TIF a)  = TIF . shiftR a
  rotate (TIF a)  = TIF . rotate a
  rotateL (TIF a) = TIF . rotateL a
  rotateR (TIF a) = TIF . rotateR a
  bitSize (TIF a) = bitSize a
  bitSizeMaybe (TIF a) = bitSizeMaybe a
  isSigned _ = False
  testBit (TIF a) = testBit a
  bit = TIF . bit
  popCount (TIF a) = popCount a

instance Show TransactionInformationFlags where
  show (TIF x) = "TIF 0x" ++ showHex x ""

-- | Reads the hexadecimal value that represents the Transaction Information Flags.
readTIF :: Text -> TransactionInformationFlags
readTIF t = case hexadecimal t of
  Left errmsg -> error $ "readTIF: " ++ errmsg
  Right (a,_) -> TIF a

tifEmpty :: TransactionInformationFlags
tifEmpty = TIF 0

-- | When set, this indicates that the web server has found an identity association for the user based upon the default (current) identity credentials supplied by 'clientIdentity' and 'signIdentity'.
tifCurrentIDMatch      :: TransactionInformationFlags
tifCurrentIDMatch      = TIF 0x01
-- | When set, this indicates that the web server has found an identity association for the user based upon the previous identity credentials supplied by 'clientPreviousID' and 'signPreviousID'.
tifPreviousIDMatch     :: TransactionInformationFlags
tifPreviousIDMatch     = TIF 0x02
-- | When set, this indicates that the IP address of the entity which requested the initial logon web page containing the SQRL link URL is the same IP address from which the SQRL client's query was received for this reply.
tifIPMatched           :: TransactionInformationFlags
tifIPMatched           = TIF 0x04
-- | When set, this indicates that this identity is disabled for SQRL-initiated authentication.
--
-- While this is set, the 'IDENT' command and any attempt at authentication will fail. This can only be reset, and the identity re-enabled for authentication, by the client issuing an 'ENABLE' command signed by the unlock request signature ('signUnlock') for the current identity. Since this signature requires the presence of the identity's RescueCode, only the strongest identity authentication is permitted to re-enable a disabled identity.
tifSQRLDisabled        :: TransactionInformationFlags
tifSQRLDisabled        = TIF 0x08
-- | When set, this indicates that the client requested one or more standard SQRL functions (through command verbs) that the server does not currently support.
--
-- The client will likely need to advise its user that whatever they were trying to do is not possible at the target website. The SQRL server will fail this query so this also implies 'tifCommandFailed'.
tifFunctionUnsupported :: TransactionInformationFlags
tifFunctionUnsupported = TIF $ 0x40 .|. 0x010
-- | The server replies with this bit set to indicate that the client's signature(s) are correct, but something about the client's query prevented the command from completing.
--
-- This is the server's way of instructing the client to retry and reissue the immediately previous command using the fresh ‘nut=’ crypto material and ‘qry=’ url the server has also just returned in its reply. The problem is likely caused by static, expired, or previously used 'SQRLNut' or qry= data. Thus, reissuing the previous command under the newly supplied server parameters would be expected to succeed. The SQRL server will not be able to complete this query so this also implies 'tifCommandFailed'.
tifTransientError      :: TransactionInformationFlags
tifTransientError      = TIF $ 0x40 .|. 0x020
-- | When set, this bit indicates that the web server had a problem successfully processing the client's query. In any such case, no change will be made to the user's account status. All SQRL server-side actions are atomic. This means that either everything succeeds or nothing is changed. This is important since clients can request multiple updates and changes at once.
--
-- If this is set without 'tifClientFailure' being set the trouble was not with the client's provided data, protocol, etc. but with some other aspect of completing the client's request. With the exception of 'tifClientFailure' status, the SQRL semantics do not attempt to enumerate every conceivable web server failure reason. The web server is free to use 'serverAsk' without arguments to explain the problem to the client's user.
tifCommandFailed       :: TransactionInformationFlags
tifCommandFailed       = TIF 0x40
-- | This is set by the server when some aspect of the client's submitted query ‑ other than expired but otherwise valid transaction state information ‑ was incorrect and prevented the server from understanding and/or completing the requested action.
--
-- This could be the result of a communications error, a mistake in the client's SQRL protocol, a signature that doesn't verify, or required signatures for the requested actions which are not present. And more specifically, this is NOT an error that the server knows would likely be fixed by having the client silently reissue its previous command; although that might still be the first recouse for the client. This is NOT an error since any such client failure will also result in a failure of the command, 'tifCommandFailed' will also be set.
tifClientFailure       :: TransactionInformationFlags
tifClientFailure       = TIF $ 0x40 .|. 0x080
-- | This is set by the server when a SQRL identity which may be associated with the query nut does not match the SQRL ID used to submit the query.
--
-- If the server is maintaining session state, such as a logged on session, it may generate SQRL query nuts associated with that logged-on session's SQRL identity. If it then receives a SQRL query using that nut, but issued with a different SQRL identity, it will fail the command with this status (which also implies 'tifCommandFailed') so that the client may inform its user that the wrong SQRL identity was used with a nut that was already associated with a different identity.
tifBadIDAssociation    :: TransactionInformationFlags
tifBadIDAssociation    = TIF $ 0x40 .|. 0x100
-- | This bit provides the SQRL client with the reason for its command failure. It is set by the server when the SQRL client has obtained the origin domain of the SQRL link, probably from the link's HREF Referer: header, forwarded it to the server in its query's “url=” parameter, and the server does not recognize the provided origin domain as valid for its SQRL links. The server fails the command, returning both this bit along with 'tifCommandFailed'. The SQRL client should inform its user that SQRL logon link was invalid.
tifInvalidLinkOrigin   :: TransactionInformationFlags
tifInvalidLinkOrigin   = TIF $ 0x40 .|. 0x200
-- | This bit allows the authenticating website to suppress the SQRL client's additional user prompting for confirmation of the remote site's server friendly name (SFN) as returned in the server's “sfn=” parameter.
--
-- In practice it will eliminate additional logon steps and delays when the server determines these are unneeded. Since this potentially eliminates last-chance user-caught site spoofing, the server must only return this bit set when it is confident that any and all additional last-chance verification is unnecessary. This bit would normally not be set in cross-device logon where the SQRL link's origin domain cannot be determined and where client provided session (CPS) cannot be provided, and thus where the SQRL client would omit the “opt=cps” and “url=” query parameters. However, non-web logon uses of the SQRL system may employ alternative verification measures, therefore all logon modes, including cross-device, should honor this bit and suppress last-chance SFN verification when this bit is present. The responsibility for this is the server's.
tifSuppressSFN         :: TransactionInformationFlags
tifSuppressSFN         = TIF 0x400

-- | Bitwise merge of two flags. @let flags = tifCurrentIDMatch `tifMerge` tifIPMatched `tifMerge` tifBadIDAssociation@
tifMerge :: TransactionInformationFlags -> TransactionInformationFlags -> TransactionInformationFlags
tifMerge (TIF x) (TIF y) = TIF $ x .|. y

-- | Check to see if the first flag(s) are set in the second. @tifTransientError `tifCheck` tifCommandFailed == True@
tifCheck :: TransactionInformationFlags -> TransactionInformationFlags -> Bool
tifCheck (TIF needle) (TIF haystack) = needle == (needle .&. haystack)

-- | A structure to contain all properties for the @server@ semantics as specified in SQRL 1.
data SQRLServerData a
  = SQRLServerData
    { serverVersion      :: SQRLVersion
    , serverNut          :: SQRLNutEx a
    , serverTransFlags   :: TransactionInformationFlags
    , serverQueryPath    :: Text
      -- ^ The “qry” parameter instructs the client what server object to query in its next (if any) query. To mitigate the potential for tampering, this qry parameter supplies the full path from the root and the object, not the scheme, domain name, or port. The scheme, domain and optional port override may only be specified once in the initial URL and cannot subsequently be changed.
    , serverFriendlyName :: Text
      -- ^ The value of this parameter is the common name by which the website is known. For example “Amazon”, “Yahoo!”, “Google”, etc. This will be displayed to the user to confirm the site they are about to authenticate to. Since the client returns this data with every command query, the web server can verify that the sfn it sent has not been tampered with and that the user saw the site's intended name.
    , serverUnlockKey    :: Maybe UnlockKey
      -- ^ The suk value is originally generated and provided to the server by the SQRL client whenever the client is creating a new identity association or modifying an existing association.
    , serverAsk          :: Maybe SQRLAsk
      -- ^ The ask parameter implements a simple but flexible means for a remote server to prompt the user with a free-form question or action confirmation message. This flexible ask facility allows the server to obtain client-signed confirmations of the user's intent through the SQRL client-server channel in situations where the web browser-to-server channel cannot offer sufficient security.
    , serverURL          :: Maybe Text
      -- ^ This value must be provided by the server in its response to any command other than “query” when the SQRL client command includes the “opt=cps” (client provided session) parameter indicating that the identity authentication was triggered by a web browser's HTML HREF request. The web browser will be awaiting a reply, which will take the form of a 301 Moved Permanently redirect to this “url=URL”, supplied by the server. The server must always supply this redirection URL, but if it does not, and if the web browser's query contained a Referer: header, the SQRL client will, as an emergency measure, return the web browser to the same page it came from as specified by the received Referer: header.
    , serverPlainExtra   :: [(Text, Text)]
    }
  deriving (Show)



-- | Takes a 'ByteString' which contains lines of key-value pairs of data (i.e. received as the @server@ parameter sent by the SQRL client) and transforms it into a structure (or an error message).
readSQRLServerData :: Binary a => ByteString -> ByteString -> ByteString -> Either String (SQRLServerData a)
readSQRLServerData cryptoKey cryptoIV t = case tf <$> dec64unpad t of
  Left errmsg -> Left $ "readSQRLServerData: " ++ errmsg
  Right (f, t') -> case readVersion <$> f "ver" of
--  (f, t') -> case readVersion <$> f "ver" of
    Nothing  -> Left "readSQRLServerData: missing ver"
    Just ver -> case f "nut" of
      Nothing   -> Left "readSQRLServerData: missing nut"
      Just nut' -> case (fromMaybe "" (readNounce "readSQRLServerData(x-nut-extra)" <$> f "x-nut-extra"), fromMaybe "" (readNounce "readSQRLServerData(x-nut-tag)" <$> f "x-nut-tag")) of
        --Nothing  -> Left "readSQRLServerData: missing x-nut-tag"
        (extra, tag) -> case fromMaybe "" (readNounce "readSQRLServerData(x-nut-nounce)" <$> f "x-nut-nounce") of
          --Nothing  -> Left "readSQRLServerData: missing x-nut-nounce"
          (ntn) -> case readTIF <$> f "tif" of
            Nothing  -> Left "readSQRLServerData: missing tif"
            Just tif -> case f "qry" of
              Nothing  -> Left "readSQRLServerData: missing qry"
              Just qry -> case f "sfn" of
                Nothing  -> Left "readSQRLServerData: missing sfn"
                Just sfn -> let
                     nut = SQRLNutEncrypted { encNutKey = cryptoKey, encNutNounce = ntn, encNutIV = iv ntn, encNutData = readNounce "readSQRLServerData(<nut>)" nut', encNutExtra = extra, encNutVer = tag }
                     suk = readKey "readSQRLServerData(suk)" <$> f "suk"
                     ask = readASK <$> f "ask"
                     pex = filter (flip notElem ["ver", "nut", "x-nut-extra", "x-nut-nounce", "x-nut-tag", "tif", "qry", "sfn", "suk", "ask"] . fst) t'
                   in Right SQRLServerData
                      { serverVersion      = ver
                      , serverNut          = nut
                      , serverTransFlags   = tif
                      , serverQueryPath    = qry
                      , serverFriendlyName = sfn
                      , serverUnlockKey    = suk
                      , serverAsk          = ask
                      , serverURL          = f "url"
                      , serverPlainExtra   = pex
                      }
  where tf dec = let t' = map (\x -> let (l', r') = T.break ('=' ==) x in (l', T.tail r')) $ filter (not . T.null) $ T.splitOn "\r\n" $
                          case TE.decodeUtf8' dec of
                           Left e -> error $ "readSQRLServerData: utf8 decoding failed: " ++ show e ++ "\n    while decoding: " ++ show dec
                           Right r -> r
                 in (flip lookup t', t')
        bsxor :: ByteString -> ByteString -> ByteString
        bsxor x y = BS.pack $ BS.zipWith xor x y
        iv nounce = let (p1, p2) = BS.splitAt (BS.length nounce) cryptoIV in BS.append (p1 `bsxor` nounce) p2














-- * Helpers

decodeASCII :: String -> ByteString -> Text
decodeASCII loc x = if BS.all (<128) x then TE.decodeUtf8 x else error $ loc ++ ": decodeASCII: outside range of ASCII."
encodeASCII :: String -> Text -> ByteString
encodeASCII loc x = let x' = TE.encodeUtf8 x in if BS.all (<128) x' then x' else error $ loc ++ ":encodeASCII: outside range of ASCII."
getWord32 :: Get Word32
getWord32 = BG.getWord32le
putWord32 :: Word32 -> Put
putWord32 = BP.putWord32le

