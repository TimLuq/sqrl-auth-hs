{-# LANGUAGE OverloadedStrings, Rank2Types #-}
module Web.Authenticate.SQRL where

import Crypto.Random
import Crypto.Cipher.AES
import qualified Crypto.Ed25519.Exceptions as ED25519
import Control.Applicative
import Control.Concurrent.MVar
import Data.Byteable
import Data.Binary
import qualified Data.Binary.Get as BG
import qualified Data.Binary.Put as BP
import Data.Bits
import Data.Time.Clock.POSIX
--import Data.QRCode
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64U
--import qualified Data.ByteString.Base64 as B64

import Control.Arrow (second)


import System.IO (hPutStrLn, stderr)
import System.IO.Error
import System.IO.Unsafe (unsafePerformIO)

import Data.String
import Numeric
import Data.Text.Read
import Data.Maybe (fromJust, mapMaybe, fromMaybe)

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

decodeASCII :: ByteString -> Text
decodeASCII = TE.decodeUtf8
encodeASCII :: Text -> ByteString
encodeASCII = TE.encodeUtf8
getWord32 :: Get Word32
getWord32 = BG.getWord32le
putWord32 :: Word32 -> Put
putWord32 = BP.putWord32le

readKey :: PublicKey k => Text -> k
readKey t = case B64U.decode $ encodeASCII t of
  Left err -> error $ "readKey: " ++ err
  Right t' -> mkPublicKey t'

readSignature :: Signature s => Text -> s
readSignature = mkSignature . publicUnlockKey . readKey

readNounce :: Text -> Nounce
readNounce = publicUnlockKey . readKey

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
  deriving (Eq)
instance Binary a => Binary (SQRLNutEx a) where
  put = putSQRLNut
  get = getSQRLNut

-- | Specialiced version of 'put'.
putSQRLNut :: Binary a => SQRLNutEx a -> Put
putSQRLNut (SQRLNut { nutIP = ip, nutTime = ut, nutCounter = cn, nutRandom = ri, nutQR = bl, nutExtra = ex }) =
  put ip  <* putWord32 ut <* putWord32 cn
  <* putWord32 ((.|.) (ri .&. 0xFFFFFFFB) $ (case ex of { Nothing -> 2 ; _ -> 0 }) .|. (if bl then 1 else 0))
  <* case ex of
       Nothing -> return ()
       Just xd -> put xd

-- | Specialiced version of 'get'.
getSQRLNut :: Binary a => Get (SQRLNutEx a)
getSQRLNut = do
  (ip, ut, en, ri) <- (,,,) <$> get <*> getWord32 <*> getWord32 <*> getWord32
  ex <- if ri .&. 2 == 0 then return Nothing else Just <$> get
  return SQRLNut { nutIP = ip, nutTime = ut, nutCounter = en, nutRandom = ri .&. 0xFFFFFFFB, nutQR = ri .&. 1 /= 0, nutExtra = ex }

{-# NOINLINE sqrlCounter #-}
sqrlCounter :: MVar (Counter, SystemRandom)
sqrlCounter = unsafePerformIO ((newGenIO :: IO SystemRandom) >>= newMVar . (,) 0)
{-# NOINLINE sqrlKey' #-}
sqrlKey' :: ByteString
sqrlKey' = unsafePerformIO $ 
  catchIOError (pad16_8 <$> BS.readFile "sqrl-nut-key.dat") $ \e -> do
    hPutStrLn stderr $
      if isDoesNotExistError e then "sqrl-nut-key.dat not found. Generating a temporary key."
      else if isPermissionError e then "sqrl-nut-key.dat is not accessible due to permissions. Generating a temporary key."
           else "sqrl-nut-key.dat can not be read because of some unknown error (" ++ show e ++ "). Generating a temporary key."
    modifyMVar sqrlCounter $ \(i, g) -> case (\(x, g') -> ((i, g'), x)) <$> genBytes 16 g of
      Left err -> fail $ "sqrlIV': default key could not be created: " ++ show err
      Right r' -> return r'

data SQRLAuthenticated = CurrentAuth IdentityKey | PreviousAuth IdentityKey | BothAuth IdentityKey IdentityKey deriving (Show, Eq)
data SQRLClientPost a
  = SQRLClientPost
    { sqrlServerData    :: SQRLServerData a
    , sqrlClientData    :: SQRLClientData
    , sqrlSignatures    :: SQRLSignatures
    , sqrlPostAll       :: [(ByteString, ByteString)]
    , sqrlAuthenticated :: SQRLAuthenticated  -- ^ 
    }
readClientPost :: Binary a => BSL.ByteString -> SQRL (SQRLClientPost a)
readClientPost b = \sqrl ->
  case f "server" of
   Nothing -> Left "readClientPost: no server data."
   Just sd -> case f "client" of
     Nothing -> Left "readClientPost: no client data."
     Just cd -> case readSQRLClientData <$> u cd of
       Left err -> Left $ "readClientPost: Client decoding failed: " ++ err
       Right (Left err) -> Left $ "readClientPost: " ++ err
       Right (Right cl) -> case u <$> f "sign" of
         Nothing -> Left "readClientPost: No signatures."
         Just (Left err) -> Left $ "readClientPost: Signatures decoding failed: " ++ err
         Just (Right sg) -> case readSQRLSignatures sg of
           Left errm -> Left $ "readClientPost: " ++ errm
           Right sig -> let signdata = BS.append sd cd
                            cid = clientIdentity cl
                            maybeError err = fromMaybe (error err)
                            cauth0 = ED25519.valid signdata (maybeError "public key size failure for cID" $ ED25519.importPublic $ publicKey cid) (ED25519.Sig $ signature $ signIdentity sig)
                            cauth1 = case (maybeError "public key size failure for pID" . ED25519.importPublic . publicKey) <$> clientPreviousID cl of
                                      Nothing  -> False
                                      Just key -> case (ED25519.Sig . signature) <$> signPreviousID sig of
                                        Nothing -> False
                                        Just sign -> ED25519.valid signdata key sign
                            cauth = if cauth1 then BothAuth cid $ fromJust $ clientPreviousID cl else CurrentAuth cid
                        in if not cauth0 then Left "readClientPost: Signature verification failed for current identity"
                           else case (\x -> runSQRL sqrl $ readSQRLServerData $ if BS.any (10==) x then x else urlcnk sqrl x) <$> u sd of
                                 Left err -> Left $ "readClientPost: Server decoding failed: " ++ err
                                 Right (Left err) -> Left $ "readClientPost: " ++ err
                                 Right (Right sv) -> Right SQRLClientPost
                                   { sqrlServerData    = sv
                                   , sqrlClientData        = cl
                                   , sqrlSignatures    = sig
                                   , sqrlPostAll       = bs
                                   , sqrlAuthenticated = cauth
                                   }
  where bs = filter (\(x, y) -> not (BS.null x || BS.null y)) $ map (\z -> let (x, y) = BSL.break (eq==) z in (BSL.toStrict x, BSL.toStrict $ BSL.tail y)) $ BSL.split amp b
        amp = fromIntegral $ fromEnum '&'
        eq  = fromIntegral $ fromEnum '='
        qrk = fromIntegral $ fromEnum '?'
        f = flip lookup bs
        u = B64U.decode
        urlcnk sqrl url = BS.intercalate "\r\n" $ BS.split amp $ BS.tail $ BS.dropWhile (qrk/=) url

clientPostData :: Binary a => ByteString -> SQRLClientPost a -> Maybe ByteString
clientPostData k = lookup k . sqrlPostAll

{-# NOINLINE sqrlIV' #-}
sqrlIV' :: ByteString
sqrlIV' = unsafePerformIO $ 
  catchIOError (pad16_8 <$> BS.readFile "sqrl-nut-iv.dat") $ \e -> do
    hPutStrLn stderr $
      if isDoesNotExistError e then "sqrl-nut-iv.dat not found. Generating a temporary IV."
      else if isPermissionError e then "sqrl-nut-iv.dat is not accessible due to permissions. Generating a temporary IV."
           else "sqrl-nut-iv.dat can not be read because of some unknown error (" ++ show e ++ "). Generating a temporary IV."
    modifyMVar sqrlCounter $ \(i, g) -> case (\(x, g') -> ((i, g'), x)) <$> genBytes 16 g of
      Left err -> fail $ "sqrlIV': default IV could not be created: " ++ show err
      Right r' -> return r'

sqrlGenNounce :: IO (Maybe Nounce)
sqrlGenNounce = sqrlRandBytes 12

sqrlRandBytes :: Int -> IO (Maybe ByteString)
sqrlRandBytes l = modifyMVar sqrlCounter $ \(i, g) -> case (\(x, g') -> ((i, g'), x)) <$> genBytes l g of
  Left err    -> hPutStrLn stderr ("sqrlRandBytes: random bytes could not be generated: " ++ show err) >> return ((i, g), Nothing)
  Right (a,b) -> return (a, Just b)

pad16_8 :: ByteString -> ByteString
pad16_8 x = let l = BS.length x
                l_ = l `mod` 8
                l' | l < 16 = 16
                   | l_ == 0 = l
                   | otherwise = l + 8 - l_
            in if l' == l then x else BS.append x $ BS.replicate (l' - l) 27

-- | Create a nut for use in SQRL.
newSQRLNut :: Binary a => IPBytes -> IO (SQRLNutEx a)
newSQRLNut ip = newSQRLNut' ip Nothing

-- | Create a nut for use in SQRL. Extra data may be encrypted together with the nut to allow session related data to be sent.
newSQRLNut' :: Binary a => IPBytes -> Maybe a -> IO (SQRLNutEx a)
newSQRLNut' ip ex = do
  (i, r) <- modifyMVar sqrlCounter $ \x -> return $ case incrementSQRL undefined x of { Left err -> (x, error $ "newSQRLNut': " ++ show err) ; Right y -> y }
  t <- truncate <$> getPOSIXTime
  return SQRLNut { nutIP = ip, nutTime = t, nutCounter = i, nutRandom = r, nutQR = False, nutExtra = ex }
  where incrementSQRL :: (Integral i, Binary r, FiniteBits r, CryptoRandomGen g) => r -> (i, g) -> Either GenError ((i, g), (i, r))
        incrementSQRL r (i, g) =  (\(x, g') -> ((i+1, g'), (i, decode $ BSL.fromStrict x))) <$> genBytes (fromIntegral $ finiteBitSize r `div` 8) g

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

-- | A type 
type SQRL t = SQRLServer sqrl => sqrl -> Either String t
type Domain = Text
type Path = Text
type Realm = Text


data SQRLUrl
  = SQRLUrl
    { sqrlUrlSecure    :: Bool
    , sqrlUrlDomain    :: Domain
    , sqrlUrlRealm     :: Realm
    , sqrlUrlPath      :: Path
    , sqrlUrlQuery     :: Text
    }
  deriving (Eq, Show)

sqrlUrl :: SQRLUrl -> Text
sqrlUrl (SQRLUrl sec dom rlm pth qry) =
  T.concat ( (if sec then "sqrl://" else "qrl://")
           : dom : "/"
           : (if T.null rlm then id else (\x -> rlm : "|" : x))
           [ pth, "?", qry]
           )

readSQRLUrl :: Text -> Either String SQRLUrl
readSQRLUrl t
  | T.take 6 t == "qrl://"  = readUrl_0 True   $ T.drop 6 t
  | T.take 7 t == "sqrl://" = readUrl_0 False  $ T.drop 7 t
  | otherwise = Left "readSQRLUrl: Invalid scheme."
  where readUrl_0 sec t' =
          let (drp, qry) = second T.tail $ T.break ('?'==) t'
              (dom, rap) = T.break (`elem` "/|") drp
              (rlm, pth) = let (r', p') = T.break ('|'==) $ T.tail rap in if T.null p' then (p', r') else (r', T.tail p')
          in if T.null dom then Left "readSQRLUrl: No domain." else if T.null qry then Left "readSQRLUrl: No querystring." else Right SQRLUrl
             { sqrlUrlSecure = sec
             , sqrlUrlDomain = dom
             , sqrlUrlRealm  = rlm
             , sqrlUrlPath   = pth
             , sqrlUrlQuery  = qry
             }



-- | An instance of a SQRL server.
class SQRLServer sqrl where
  -- | The IV used for encryption of 'SQRLNut's.
  sqrlIV :: sqrl -> ByteString
  sqrlIV = const sqrlIV'
  -- | The key used for encryptions of 'SQRLNut's.
  sqrlKey :: sqrl -> ByteString
  sqrlKey = const sqrlKey'
  -- | The versions supported by this server (default is only 1).
  sqrlVersion :: sqrl -> SQRLVersion
  sqrlVersion = const sqrlVersion1
  -- | If the SQRL server is runnung HTTPS.
  sqrlTLS :: sqrl -> Bool
  -- | The domain (and optional port) the SQRL server is running at.
  sqrlDomain :: sqrl -> Text
  -- | The path the SQRL server is listening to.
  sqrlPath :: sqrl -> Text

-- | A future compatible way to run a SQRL server.
runSQRL :: SQRLServer sqrl => sqrl -> SQRL t -> Either String t
runSQRL sqrl sqrlf = sqrlf sqrl

type AskResponse = (Int, Maybe Text)
-- | Reads the response of an ask. According to the spec (as of 2015-06-17) the text is not base64 encoded, just plain utf-8.
readAskResponse :: Maybe Text -> Text -> AskResponse
readAskResponse t w = (read $ T.unpack w, t)

-- | Get the index of the default button for an agreed 'SQRLVersion'.
askResponseButtonDefault :: VersionNum -> Int
askResponseButtonDefault = const 3

-- | Get which button was pressed by the client.
askResponseButton :: AskResponse -> Int
askResponseButton = fst

-- | Get the input provided by the user, if any.
askResponseText :: AskResponse -> Maybe Text
askResponseText = snd

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
    , clientIdentity      :: IdentityKey                -- ^ The current identity of the user.
    , clientPreviousID    :: Maybe IdentityKey          -- ^ The previous identity of the user if the identity has been changed.
    , clientServerUnlock  :: Maybe ServerUnlockKey      -- ^ The key used to unlock the users identity.
    , clientVerifyUnlock  :: Maybe VerifyUnlockKey      -- ^ The key used to verify an unlock action.
    }

-- | A structure representing the @ids@ parameter sent from a SQRL client.
data SQRLSignatures
  = SQRLSignatures
    { signIdentity        :: IdentitySignature          -- ^ A signature by the users current identity.
    , signPreviousID      :: Maybe IdentitySignature    -- ^ A signature signed by the users previous identity.
    , signUnlock          :: Maybe UnlockSignature      -- ^ A signtaure to verify an unlock action.
    }

-- | A user may be asked to fill in a value and may use one out of two buttons (or OK by default) to send back the response.
data SQRLAsk
  = SQRLAsk
    { askMessage   :: Text         -- ^ The message to be shown to the user.
    , askInput     :: Bool         -- ^ If the user is expected to input a response message (such as a new username).
    , askButtons   :: [AskButton]  -- ^ A list of buttons.
    }

-- | Reads a Base64 encoded version of the @ask=@ server option.
readASK :: Text -> SQRLAsk
readASK t = case B64U.decode $ encodeASCII t of
  Left errmsg -> error $ "readASK: " ++ errmsg
  Right t' -> readASK' $ TE.decodeUtf8 t'
-- | Reads a text version of the server ask. See 'readASK' for a version that also decodes base64.
readASK' :: Text -> SQRLAsk
readASK' t = case T.split ('~'==) t of
              []      -> SQRLAsk "" False []
              [x]     -> SQRLAsk x False []
              (x:b:r) -> SQRLAsk x (not (T.null b) && T.head b == '1') $ map readAskButton r
  where readAskButton x = let (t', u) = T.break (';'==) x in if T.null u then (t', Nothing) else (t', Just $ T.tail u)

type AskButton = (Text, Maybe Text)

type VersionNum = Int

data SQRLVersion
  = VersionList     [SQRLVersion]
  | VersionNum      VersionNum
  | VersionInterval (VersionNum, VersionNum)
  deriving (Eq)

sqrlVersion1 :: SQRLVersion
sqrlVersion1 = VersionNum 1

-- | Extracts the highest version contained within two version specifications.
versionCompatible :: SQRLVersion -> SQRLVersion -> Maybe VersionNum
versionCompatible (VersionNum x) (VersionNum y) = if x == y then Just x else Nothing
versionCompatible (VersionInterval (xl, xh)) (VersionNum y) = if xl <= y && xh >= y then Just y else Nothing
versionCompatible (VersionInterval (xl, xh)) (VersionInterval (yl, yh)) = if xl <= yh && xh >= yl then Just (if yh < xh then yh else xh) else Nothing
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
readSQRLClientData t = case tf <$> B64U.decode t of
  Left errmsg -> Left $ "readSQRLClientData: " ++ errmsg
  Right f -> case readVersion <$> f "ver" of
    Nothing  -> Left "readSQRLClientData: missing ver"
    Just ver -> case readCommand <$> f "cmd" of
      Nothing  -> Left "readSQRLClientData: missing cmd"
      Just cmd -> case readKey <$> f "idk" of
        Nothing  -> Left "readSQRLClientData: missing idk"
        Just idk -> Right SQRLClientData
          { clientVersion      = ver
          , clientCommand      = cmd
          , clientOptions      = readClientOptions <$> f "opt"
          , clientAskResponse  = readAskResponse (f "txt") <$> f "btn"
          , clientIdentity     = idk
          , clientPreviousID   = readKey <$> f "pidk"
          , clientServerUnlock = readKey <$> f "suk"
          , clientVerifyUnlock = readKey <$> f "vuk"
          }
  where tf dec = let t' = map (\x -> let (l', r') = T.break ('=' ==) x in (l', T.tail r')) $ filter (not . T.null) $ T.lines $ TE.decodeUtf8 dec in flip lookup t'

-- | Reads the supported version(s) of a client or server.
readVersion :: Text -> SQRLVersion
readVersion t = case T.split (','==) t of
  [x] -> readVersion' x
  xs  -> VersionList $ map readVersion' xs
  where readVersion' = VersionNum . read . T.unpack

-- | Takes a 'ByteString' (most likely from the @ids=@ parameter sent by the SQRL client) and return a structure or an error message.
readSQRLSignatures :: ByteString -> Either String SQRLSignatures
readSQRLSignatures t = case tf <$> B64U.decode t of
  Left errmsg -> Left $ "readSQRLSignatures: " ++ errmsg
  Right f -> case readSignature <$> f "ids" of
    Nothing  -> Left "readSQRLSignatures: missing ids"
    Just ids -> Right SQRLSignatures
      { signIdentity       = ids
      , signPreviousID     = readSignature <$> f "pids"
      , signUnlock         = readSignature <$> f "urs"
      }
  where tf dec = let t' = map (\x -> let (l', r') = T.break ('=' ==) x in (l', T.tail r')) $ filter (not . T.null) $ T.lines $ TE.decodeUtf8 dec in flip lookup t'

-- | A collection of flags conveying information about execution state of a command.
newtype TransactionInformationFlags = TIF Int deriving (Eq, Read)

instance Show TransactionInformationFlags where
  show (TIF x) = "TIF 0x" ++ showHex x ""

-- | Reads the hexadecimal value that represents the Transaction Information Flags.
readTIF :: Text -> TransactionInformationFlags
readTIF t = case hexadecimal t of
  Left errmsg -> error $ "readTIF: " ++ errmsg
  Right (a,_) -> TIF a

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
tifFunctionUnsupported = TIF $ 0x40 + 0x010
-- | The server replies with this bit set to indicate that the client's signature(s) are correct, but something about the client's query prevented the command from completing.
--
-- This is the server's way of instructing the client to retry and reissue the immediately previous command using the fresh ‘nut=’ crypto material and ‘qry=’ url the server has also just returned in its reply. The problem is likely caused by static, expired, or previously used 'SQRLNut' or qry= data. Thus, reissuing the previous command under the newly supplied server parameters would be expected to succeed. The SQRL server will not be able to complete this query so this also implies 'tifCommandFailed'.
tifTransientError      :: TransactionInformationFlags
tifTransientError      = TIF $ 0x40 + 0x020
-- | When set, this bit indicates that the web server had a problem successfully processing the client's query. In any such case, no change will be made to the user's account status. All SQRL server-side actions are atomic. This means that either everything succeeds or nothing is changed. This is important since clients can request multiple updates and changes at once.
--
-- If this is set without 'tifClientFailure' being set the trouble was not with the client's provided data, protocol, etc. but with some other aspect of completing the client's request. With the exception of 'tifClientFailure' status, the SQRL semantics do not attempt to enumerate every conceivable web server failure reason. The web server is free to use 'serverAsk' without arguments to explain the problem to the client's user.
tifCommandFailed       :: TransactionInformationFlags
tifCommandFailed       = TIF 0x40
-- | This is set by the server when some aspect of the client's submitted query ‑ other than expired but otherwise valid transaction state information ‑ was incorrect and prevented the server from understanding and/or completing the requested action.
--
-- This could be the result of a communications error, a mistake in the client's SQRL protocol, a signature that doesn't verify, or required signatures for the requested actions which are not present. And more specifically, this is NOT an error that the server knows would likely be fixed by having the client silently reissue its previous command; although that might still be the first recouse for the client. This is NOT an error since any such client failure will also result in a failure of the command, 'tifCommandFailed' will also be set.
tifClientFailure       :: TransactionInformationFlags
tifClientFailure       = TIF $ 0x40 + 0x080
-- | This is set by the server when a SQRL identity which may be associated with the query nut does not match the SQRL ID used to submit the query.
--
-- If the server is maintaining session state, such as a logged on session, it may generate SQRL query nuts associated with that logged-on session's SQRL identity. If it then receives a SQRL query using that nut, but issued with a different SQRL identity, it will fail the command with this status (which also implies 'tifCommandFailed') so that the client may inform its user that the wrong SQRL identity was used with a nut that was already associated with a different identity.
tifBadIDAssociation    :: TransactionInformationFlags
tifBadIDAssociation    = TIF $ 0x40 + 0x100

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
    , serverFriendlyName :: Text
    , serverUnlockKey    :: Maybe UnlockKey
    , serverAsk          :: Maybe SQRLAsk
    , serverPlainExtra   :: [(Text, Text)]
    }

-- | Takes a 'ByteString' which contains lines of key-value pairs of data (i.e. received as the @server@ parameter sent by the SQRL client) and transforms it into a structure (or an error message).
readSQRLServerData :: Binary a => ByteString -> SQRL (SQRLServerData a)
readSQRLServerData t sqrl = case tf <$> B64U.decode t of
  Left errmsg -> Left $ "readSQRLServerData: " ++ errmsg
  Right (f, t') -> case readVersion <$> f "ver" of
    Nothing  -> Left "readSQRLServerData: missing ver"
    Just ver -> case f "nut" of
      Nothing  -> Left "readSQRLServerData: missing nut"
      Just nt' -> let nut' = readNounce $ case f "nut-extra" of { Nothing -> nt' ; Just nte -> T.append nt' nte } in case readNounce <$> f "nut-tag" of
        Nothing  -> Left "readSQRLServerData: missing nut-tag"
        Just ntt -> case readNounce <$> f "nut-nounce" of
          Nothing  -> Left "readSQRLServerData: missing nut-nounce"
          Just ntn -> case readTIF <$> f "tif" of
            Nothing  -> Left "readSQRLServerData: missing tif"
            Just tif -> case f "qry" of
              Nothing  -> Left "readSQRLServerData: missing qry"
              Just qry -> case f "sfn" of
                Nothing  -> Left "readSQRLServerData: missing sfn"
                Just sfn -> let
                     (nut, tag) = decryptGCM (initAES $ sqrlKey sqrl) (iv ntn) "HS-SQRL" nut'
                     suk = readKey <$> f "suk"
                     ask = readASK <$> f "ask"
                     pex = filter (flip notElem ["ver", "nut", "nut-extra", "nut-nounce", "nut-tag", "tif", "qry", "sfn", "suk", "ask"] . fst) t'
                   in if toBytes tag /= ntt then Left "readSQRLServerData: tag mismatch" else Right SQRLServerData
                      { serverVersion      = ver
                      , serverNut          = decode $ BSL.fromStrict nut
                      , serverTransFlags   = tif
                      , serverQueryPath    = qry
                      , serverFriendlyName = sfn
                      , serverUnlockKey    = suk
                      , serverAsk          = ask
                      , serverPlainExtra   = pex
                      }
  where tf dec = let t' = map (\x -> let (l', r') = T.break ('=' ==) x in (l', T.tail r')) $ filter (not . T.null) $ T.lines $ TE.decodeUtf8 dec in (flip lookup t', t')
        bsxor :: ByteString -> ByteString -> ByteString
        bsxor x y = BS.pack $ BS.zipWith xor x y
        iv nounce = let (p1, p2) = BS.splitAt (BS.length nounce) (sqrlIV sqrl) in BS.append (p1 `bsxor` nounce) p2


-- | Creates an URL for use with SQRL (used to create a QR Code or browser links).
sqrlURL :: Binary a => SQRLNutEx a -> Nounce -> SQRL Text
sqrlURL nut nounce sqrl = Right $ T.append (T.append (T.append (if sqrlTLS sqrl then "sqrl://" else "qrl://") (sqrlDomain sqrl)) path') $ decodeASCII cryptUrl'
  where path = sqrlPath sqrl
        path' = if T.null path then "/" else T.append path $ case T.findIndex ('?' ==) path of { Nothing -> "?nut=" ; _ -> "&nut=" }
        bsxor :: ByteString -> ByteString -> ByteString
        bsxor x y = BS.pack $ BS.zipWith xor x y
        iv = let (p1, p2) = BS.splitAt (BS.length nounce) (sqrlIV sqrl) in BS.append (p1 `bsxor` nounce) p2
        crypt = encryptGCM (initAES $ sqrlKey sqrl) iv "HS-SQRL" $ BSL.toStrict $ encode nut
        cryptUrl' =
          let (base', tag)  = crypt
              (base, extra) = BS.splitAt 16 base'
          in (if BS.null extra then id else flip BS.append (BS.append "&nut-extra=" $ B64U.encode extra))
             $ BS.append (BS.append (BS.take 22 $ B64U.encode base) $ BS.append "&nut-nounce=" $ B64U.encode nounce)
             $ BS.append "&nut-tag=" $ BS.take 22 $ B64U.encode $ toBytes tag

-- * SQRL generator  


{-
-- | Generate a SQRL login button which is, of course, a QR Code.
htmlSQRLLogin :: Binary a => Text -> Text -> SQRLNutEx a -> IO Html
htmlSQRLLogin tls domain path nut = do
  nounce0 <- modifyMVar sqrlCounter $ \(i, g) -> (\(x, g') -> ((i, g'), x)) <$> genBytes 12 g
  qrdata  <- qr $ cryptUrl nounce0 nut { nutQR = True }
  nounce1 <- modifyMVar sqrlCounter $ \(i, g) -> (\(x, g') -> ((i, g'), x)) <$> genBytes 12 g
  return $ a   ! class_ "sqrl" ! href (toValue $ cryptUrl nounce1 nut { nutQR = False })
         $ img ! src (toValue $ T.append "data:image/png;base64," qrdata)
  where black = rgb 0x00 0x00 0x00
        white = rgb 0xFF 0xFF 0xFF
        qrplt = [white, black]
        cryptUrl = sqrlURL tls domain path
        bwcol p l w = foldr (\n p' -> (if testBit w n then black else white) : p') p [(0 .. (l-1))]
        qr :: Text -> AttributeValue
        qr t = let qrc = encodeByteString (TE.encodeUtf8 t) Nothing QR_ECLEVEL_M QR_MODE_EIGHT
                   qrl = getQRCodeWidth qrc
                   scanline r = let (pt0, pt1) = splitAt (qrl `div` 8) in yield $ foldr (\bits colors -> bwcol colors 8 bits) (if null pt1 then [] else bwcol [] (qrl `mod` 8) (head pt1)) pt0
                   scanlines = toProducer $ mapM_ scanline $ toMatrix qrc
               in decodeASCII $ BS.concat $ runIdentity $ pngSource (mkPNGFromPalette qrl qrl qrplt scanlines) $= encodeBase64 $$ CL.consume

-}
