module Web.Authentification.SQRL

import Crypto.Random
import Crypto.Cipher.AES
import Control.Applicative
import Control.Concurrent.MVar
import Data.Binary
import Data.Bits
import Data.Time.Clock.POSIX
import Data.QRCode
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Base64 as B64

type IPBytes = (Word8, Word8, Word8, Word8)
type UnixTime = Word32
type Counter = Word32
type RandomInt = Word32

type SQRLNut = SQRLNutEx ()

data SQRLNutEx a
  = SQRLNut
    { nutIP      :: IPBytes
    , nutTime    :: UnixTime
	, nutCounter :: Counter
	, nutRandom  :: RandomInt
	, nutQR      :: Bool
	, nutExtra   :: Binary a => Maybe a
	}
  deriving (Eq)
instance Binary a => Binary (SQRLNutEx a) where
  put = putSQRLNut
  get = getSQRLNut

--| Specialiced version of 'put'.
putSQRLNut :: Binary a => SQRLNutEx a -> Put
putSQRLNut (SQRLNut { nutIP = (a, b, c, d), nutTime = ut, nutCounter = cn, nutRandom = ri, nutQR = bl, nutExtra = ex }) =
  putWord8 a <* putWord8 b <* putWord8 c <* putWord8 d
  <* putWord32 ut <* putWord32 cn
  <* putWord32 $ (.|.) (ri .&. 0xFFFFFFFB) $ (if ex /= Nothing then 2 else 0) .|. (if nutQR then 1 else 0)
  <* case ex of
       Nothing -> return ()
	   Just xd -> put xd

--| Specialiced version of 'get'.
getSQRLNut :: Binary a => Get (SQRLNutEx a)
getSQRLNut = do
  (ip, ut, en, ri) <- (,,,) <$> ((,,,) <$> getWord8 <*> getWord8 <*> getWord8 <*> getWord8) <*> getWord32 <*> getWord32 <*> getWord32
  ex <- if ri .&. 2 == 0 then return Nothing else Just <$> get
  return $ SQRLNut { nutIP = ip, nutTime = ut, nutCounter = cn, nutRandom = ri .&. 0xFFFFFFFB, nutQR = ri .&. 1 /= 0, nutExtra = ex }

{-# NOINLINE sqrlCounter #-}
--sqrlCounter :: MVar Word32
sqrlCounter = unsafePerformIO (newGenIO >>= newMVar . ((,) 0))
{-# NOINLINE sqrlKey #-}
sqrlKey :: ByteString
sqrlKey = unsafePerformIO $ modifyMVar sqrlCounter $ \(i, g) -> (\(x, g') -> ((i, g'), x)) <$> genBytes 16 g
{-# NOINLINE sqrlKey #-}
sqrlIV :: ByteString
sqrlIV = unsafePerformIO $ modifyMVar sqrlCounter $ \(i, g) -> (\(x, g') -> ((i, g'), x)) <$> genBytes 16 g

--| Create a nut for use in SQRL.
newSQRLNut :: Binary a => IPBytes -> IO (SQRLNutEx a, SQRLNutEx a)
newSQRLNut ip = newSQRLNut ip Nothing

--| Create a nut for use in SQRL. Extra data may be encrypted together with the nut to allow session related data to be sent.
newSQRLNut' :: Binary a => IPBytes -> Maybe a -> IO (SQRLNutEx a, SQRLNutEx a)
newSQRLNut' ip ex = do
  (i, r) <- modifyMVar sqrlCounter incrementSQRL
  t <- truncate <$> getPOSIXTime
  return SQRLNutEx { nutIP = ip, nutTime = t, nutCounter = i, nutRandom = r, nutQR = False, nutExtra = ex }
  where incrementSQRL (i, g) = (\(x, g') -> ((i+1, g'), (i, decode x))) <$> genBytes 4 g

--| A command issued by the SQRL Client.
data SQRLCommandAction = QUERY | IDENT | DISABLE | ENABLE | REMOVE | CMD Text deriving (Show, Eq, Read)

--| Reads a single command.
readCommand :: Text -> SQRLCommandAction
readCommand "query"   = QUERY
readCommand "ident"   = IDENT
readCommand "disable" = DISABLE
readCommand "enable"  = ENABLE
readCommand "remove"  = REMOVE
readCommand x         = CMD x


--| A structure representing the @client@ parameter sent by the SQRL client.
data SQRLClient
  = SQRLClient
    { clientVersion       :: SQRLVersion                --^ The client version support.
	, clientCommand       :: SQRLCommandAction          --^ The command the client want to execute.
	, clientOptions       :: Maybe SQRLClientOptions
	, clientAskValue      :: Maybe AskValue
	, clientIdentity      :: IdentityKey
	, clientPreviousID    :: Maybe IdentityKey
	, clientServerUnlock  :: Maybe ServerUnlockKey
	, clientVerifyUnlock  :: Maybe VerifyUnlockKey
	}

--| A structure representing the @ids@ parameter sent from a SQRL client.
data SQRLSignatures
  = SQRLSignatures
    { signIdentity        :: IdentitySignature
	, signPreviousID      :: Maybe IdentitySignature
	, signUnlock          :: Maybe UnlockSignature
	}

--| Takes a 'ByteString' (most likely from the @client@ parameter sent by the SQRL client) and returns a structure or an error message.
mkSQRLClient :: ByteString -> Either String SQRLClient
mkSQRLClient t =
  (readVersion <$> f "ver") >>= \case
    Nothing  -> Left "mkSQRLClient: missing ver"
	Just ver -> (readCommand <$> f "cmd") >>= \case
	  Nothing  -> Left "mkSQRLClient: missing cmd"
	  Just cmd -> (readKey <$> f "idk") >>= \case
		Nothing  -> Left "mkSQRLClient: missing idk"
		Just idk -> Right $ SQRLCclient
		  { clientVersion      = ver
		  , clientCommand      = cmd
		  , clientOptions      = readClientOptions <$> f "opt"
		  , clientAskValue     = f "val"
		  , clientIdentity     = idk
		  , clientPerviousID   = readKey <$> f "pidk"
		  , clientServerUnlock = readKey <$> f "suk"
		  , clientVerifyUnlock = readKey <$> f "vuk"
		  }
  where f = flip lookup t'
        t' = map (\x -> let (l', r') = T.breakOn ('=' ==) in (l', T.tail r')) $ filter (not . T.null) $ T.lines $ TE.decodeUTF8 $ B64U.decode t
		readKey = B64U.decode

readVersion :: Text -> SQRLVersion
readVersion = read . read . show -- TODO: Absurdly ineffective and only works with one supported version

--| Takes a 'ByteString' (most likely from the @ids@ parameter sent by the SQRL client) and return a structure or an error message.
mkSQRLSignatures :: ByteString -> Either String SQRLSignatures
mkSQRLSignatures t =
  (readSignature <$> f "ids") >>= \case
    Nothing  -> Left "mkSQRLSignatures: missing ids"
    Just ids -> Right $ SQRLSignatures
	  { signIdentity       = ids
	  , signPreviousID     = readSignature <$> f "pids"
	  , signUnlock         = readSignature <$> f "urs"
	  }
  where f = flip lookup t'
        t' = map (\x -> let (l', r') = T.breakOn ('=' ==) in (l', T.tail r')) $ filter (not . T.null) $ T.lines $ TE.decodeUTF8 $ B64U.decode t
		readSignature = B64U.decode

--| A collection of flags conveying information about execution of command.
newtype TransactionInformationFlags = TIF Int deriving (Eq, Show, Read)

tifCurrentIDMatch      = TIF 0x01
tifPreviousIDMatch     = TIF 0x02
tifIPMatched           = TIF 0x04
tifSQRLDisabled        = TIF 0x08
tifFunctionUnsupported = TIF $ 0x40 + 0x010
tifTransientError      = TIF $ 0x40 + 0x020
tifCommandFailed       = TIF 0x40
tifClientFailure       = TIF $ 0x40 + 0x080
tifBadIDAssociation    = TIF $ 0x40 + 0x100

--| Bitwise merge of two flags. @let flags = tifCurrentIDMatch `tifMerge` tifIPMatched `tifMerge` tifBadIDAssociation@
tifMerge :: TransactionInformationFlags -> TransactionInformationFlags -> TransactionInformationFlags
tifMerge (TIF x) (TIF y) = TIF $ x .|. y

--| Check to see if the first flag(s) are set in the second. @tifTransientError `tifCheck` tifCommandFailed == True@
tifCheck :: TransactionInformationFlags -> TransactionInformationFlags -> Bool
tifCheck (TIF needle) (TIF haystack) = needle == (needle .&. heystack)

--| A structure to contain all properties for the @server@ semantics as specified in SQRL 1.
data SQRLServerData a
  = SQRLServeraData
    { serverVersion      :: SQRLVersion
	, serverNut          :: SQRLNutEx a
	, serverTransFlags   :: TransactionInformationFlags
	, serverQueryPath    :: Text
	, serverFriendlyName :: Text
	, serverUnlockKey    :: Maybe UnlockKey
	, serverAsk          :: Maybe SQRLAsk
	, serverPlainExtra   :: [(Text, Text)]
	}

--| Takes a 'ByteString' which contains lines of key-value pairs of data (i.e. received as the @server@ parameter sent by the SQRL client) and transforms it into a structure (or an error message).
mkSQRLServerData :: ByteString -> Either String (SQRLServerData a)
mkSQRLServerData t =
  case readVersion <$> f "ver" of
    Nothing  -> Left "mkSQRLServerData: missing ver"
	Just ver -> case f "nut" of
	  Nothing  -> Left "mkSQRLServerData: missing nut"
	  Just nt' -> let nut' = case f "nut-extra" of { Nothing -> nt' ; Just nte -> T.append nt' ntd } in case f "nut-tag" of
	    Nothing  -> Left "mkSQRLServerData: missing nut-tag"
		Just ntt -> case readNounce <$> f "nut-nounce" of
		  Nothing  -> Left "mkSQRLServerData: missing nut-nounce"
		  Just ntn -> case readTIF <$> f "tif" of
		    Nothing  -> Left "mkSQRLServerData: missing tif"
		    Just tif -> case f "qry" of
		      Nothing  -> Left "mkSQRLServerData: missing qry"
		      Just qry -> case f "sfn" of
                Nothing  -> Left "mkSQRLServerData: missing sfn"
		    	Just sfn -> case  of
				    (nut, tag) = decryptGCM (initAES sqrlKey) (iv ntt) "HS-SQRL" nut'
			        suk = f "suk"
			        vuk = readASK <$> f "ask"
				    pex = filter (flip notElem ["ver", "nut", "nut-extra", "nut-nounce", "nut-tag", "tif", "qry", "sfn", "suk", "ask"] . fst) t'
			      in if tag /= ntt then Left "mkSQRLServerData: tag mismatch" else Right $ SQRLServerData
		             { serverVersion      = ver
					 , serverNut          = decode nut
					 , serverTransFlags   = tif
					 , serverQueryPath    = qry
					 , serverFriendlyName = sfn
					 , serverUnlockKey    = suk
					 , serverAsk          = ask
					 , serverPlainExtra   = pex
		             }
  where f = flip lookup t'
        t' = map (\x -> let (l', r') = T.breakOn ('=' ==) in (l', T.tail r')) $ filter (not . T.null) $ T.lines $ TE.decodeUTF8 $ B64U.decode t
		readKey = B64U.decode
        bsxor = B.pack . B.zipWith xor
		iv = let (p1, p2) = BS.breakAt (BS.length nounce) sqrlIV in BS.append (p1 `bsxor` nounce) p2


-- * SQRL generator  

--| Creates an URL for use with SQRL (used to create a QR Code or browser links).
sqrlURL :: Bool -> Text -> Text -> SQRLNutEx a -> Text
sqrlURL tls domain path nut nounce =  T.append (T.append (T.append (if tls then "sqrl://" else "qrl://") domain) path') . cryptUrl'
  where path' = if T.null path then "/" else (T.append path $ case T.findIndex ('?' ==) path of { Nothing -> "?nut=" ; _ -> "&nut=" })
        bsxor = B.pack . B.zipWith xor
		iv = let (p1, p2) = BS.breakAt (BS.length nounce) sqrlIV in BS.append (p1 `bsxor` nounce) p2
        crypt = encryptGCM (initAES sqrlKey) (iv nounce) "HS-SQRL" $ encode nut
		cryptUrl' =
		  let ((base, extra), tag) = fmap (BS.splitAt 16) $ crypt nut nounce
		  in (if BS.null extra then id else flip BS.append (BS.append "&nut-extra=" $ B64U.encode extra))
		     $ BS.append (B64U.encode base) $ BS.append "&nut-nounce=" $ B64U.encode nounce

--| Generate a SQRL login button which is, of course, a QR Code.
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
		bwcol p l w = foldr (\n p' -> (if testBit w n then black else white) : p') p [(0 .. (l-1)]
		qr :: Text -> AttributeValue
		qr t = let qrc = encodeByteString (TE.encodeUtf8 t) Nothing QR_ECLEVEL_M QR_MODE_EIGHT
		           qrl = getQRCodeWidth qrc
				   scanline r = let (pt0, pt1) = splitAt (qrl `div` 8) in yield $ foldr (\bits colors -> bwcol colors 8 bits) (if null pt1 then [] else bwcol [] (qrl `mod` 8) (head pt1)) pt0
				   scanlines = toProducer $ mapM_ scanline $ toMatrix qrc
		       in TE.decodeASCII $ BS.concat $ runIdentity $ pngSource (mkPNGFromPalette qrl qrl qrplt scanlines) $= encodeBase64 $$ CL.consume
		       
