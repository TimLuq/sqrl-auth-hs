{-# LANGUAGE OverloadedStrings, Rank2Types #-}
module Web.Authenticate.SQRL where

import Web.Authenticate.SQRL.Types

--import Data.Char (isDigit, isAlpha)
import Crypto.Random
import Crypto.Cipher.AES
import qualified Crypto.Ed25519.Exceptions as ED25519
import Control.Applicative
import Control.Concurrent.MVar
import Data.Byteable
import Data.Binary
import Data.Bits
import Data.Time.Clock.POSIX
--import Data.QRCode
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS



import System.IO (hPutStrLn, stderr)
import System.IO.Error
import System.IO.Unsafe (unsafePerformIO)

import Data.Maybe (fromJust, fromMaybe)


-- | A type 
type SQRL t = SQRLServer sqrl => sqrl -> Either String t


-- | Trololololo - any container which contains a nut, or two.
class NutSack f where
  tickleNuts :: (SQRLNutEx a -> SQRLNutEx a) -> f a -> f a
  crackNuts :: Binary a => f a -> f a
  crackNuts = tickleNuts (\x -> case decryptSQRLNut x of { Left e -> error ("crackNuts: " ++ e) ; Right r -> r })
  wrapNuts :: (Binary a, SQRLServer sqrl) => sqrl -> Nounce -> f a -> f a
  wrapNuts sqrl nounce = tickleNuts (encryptSQRLNut sqrl nounce)
instance NutSack SQRLNutEx where
  tickleNuts f = f
instance NutSack SQRLServerData where
  tickleNuts f x = x { serverNut = f (serverNut x) }

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
readClientPost :: Binary a => BSL.ByteString -> SQRL (SQRLClientPost a, SQRLAuthenticated)
readClientPost b = \sqrl ->
  case f "server" of
   Nothing -> Left "readClientPost: no server data."
   Just sd -> case f "client" of
     Nothing -> Left "readClientPost: no client data."
     Just cd -> case readSQRLClientData cd of
--       Left err -> Left $ "readClientPost: Client decoding failed: " ++ err
--       Right (Left err) -> Left $ "readClientPost: " ++ err
--       Right (Right cl) -> case u <$> f "sign" of
       Left err -> Left $ "readClientPost: " ++ err
       Right cl -> case f "ids" of
         Nothing -> Left "readClientPost: No signatures."
         Just sg -> case readSQRLSignatures sg of
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
                           else case u sd >>= fsdata sqrl of
                                 Left err -> Left $ "readClientPost: Server decoding failed: " ++ err
                                 Right sv -> Right (SQRLClientPost
                                   { sqrlServerData    = sv
                                   , sqrlClientData    = cl
                                   , sqrlSignatures    = sig
                                   , sqrlPostAll       = bs
                                   }, cauth)
  where bs = filter (\(x, y) -> not (BS.null x || BS.null y)) $ map (\z -> let (x, y) = BSL.break (eq==) z in (BSL.toStrict x, BSL.toStrict $ BSL.tail y)) $ BSL.split amp b
        amp = (fromIntegral $ fromEnum '&') :: Word8
        eq  = (fromIntegral $ fromEnum '=') :: Word8
        f = flip lookup bs
        u = dec64unpad
        fsdata :: (SQRLServer sqrl, Binary a) => sqrl -> ByteString -> Either String (Either SQRLUrl (SQRLServerData a))
        fsdata sqrl x = if BS.take 6 x `elem` ["sqrl:/", "qrl://"]
                        then onleft (\e -> Left ("sqrl-link decoding error: " ++ show e)) (TE.decodeUtf8' x) >>= readSQRLUrl >>= \r -> Right (Left r)
                        else runSQRL sqrl (serverReadSQRLServerData x) >>= \r -> Right (Right r)
        onleft g (Left x) = g x
        onleft _ (Right x) = Right x




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

data SQRLServerLocal = SQRLServerLocal
instance SQRLServer SQRLServerLocal where
  sqrlTLS _ = False
  sqrlDomain _ = "localhost"
  sqrlPath _ = "/sqrl"

-- | A future compatible way to run a SQRL server.
runSQRL :: SQRLServer sqrl => sqrl -> SQRL t -> Either String t
runSQRL sqrl sqrlf = sqrlf sqrl


-- | Server specialices version of 'readSQRLServerData'.
serverReadSQRLServerData :: Binary a => ByteString -> SQRL (SQRLServerData a)
serverReadSQRLServerData t sqrl = readSQRLServerData (sqrlKey sqrl) (sqrlIV sqrl) t


-- | Encrypts a nut. If the nut is already encrypted this is the identity.
encryptSQRLNut :: (SQRLServer sqrl, Binary a) => sqrl -> Nounce -> SQRLNutEx a -> SQRLNutEx a
encryptSQRLNut _ _ n@(SQRLNutEncrypted {}) = n
encryptSQRLNut sqrl nounce n = SQRLNutEncrypted
  { encNutIV = iv
  , encNutKey = key
  , encNutVer = toBytes tag
  , encNutData = base
  , encNutExtra = extra
  , encNutNounce = nounce
  }
  where (base, extra) = BS.splitAt 16 crypt
        key = sqrlKey sqrl
        (crypt, tag) = encryptGCM (initAES key) iv "HS-SQRL" $ BSL.toStrict $ encode n
        bsxor :: ByteString -> ByteString -> ByteString
        bsxor x y = BS.pack $ BS.zipWith xor x y
        iv = let (p1, p2) = BS.splitAt (BS.length nounce) (sqrlIV sqrl) in BS.append (p1 `bsxor` nounce) p2

-- | Decrypts a nut. If the nut is already decrypted this is the identity.
decryptSQRLNut :: Binary a => SQRLNutEx a -> Either String (SQRLNutEx a)
decryptSQRLNut n@(SQRLNut {}) = Right n
decryptSQRLNut (SQRLNutEncrypted { encNutIV = iv, encNutKey = key, encNutVer = tag, encNutData = base, encNutExtra = extra }) = r
  where (nutd, tag') = decryptGCM (initAES key) iv "HS-SQRL" (BS.append base extra)
        r = decode (BSL.fromStrict nutd) >>= \nut -> if tag == toBytes tag' then Right nut else Left "TAG MISMATCH"



-- | Creates an URL for use with SQRL (used to create a QR Code or browser links).
sqrlURL :: Binary a => SQRLNutEx a -> Nounce -> SQRL Text
sqrlURL nut nounce sqrl = Right $ T.append (T.append (T.append (if sqrlTLS sqrl then "sqrl://" else "qrl://") (sqrlDomain sqrl)) path') $ decodeASCII "sqrlURL" cryptUrl'
  where path = sqrlPath sqrl
        path' = if T.null path then "/" else T.append path $ case T.findIndex ('?' ==) path of { Nothing -> "?nut=" ; _ -> "&nut=" }
        (SQRLNutEncrypted { encNutVer = tag, encNutData = base, encNutExtra = extra }) = encryptSQRLNut sqrl nounce nut
        cryptUrl' =
          (if BS.null extra then id else flip BS.append (BS.append "&x-nut-extra=" $ enc64unpad extra))
          $ BS.append (BS.append (BS.take 22 $ enc64unpad base) $ BS.append "&x-nut-nounce=" $ enc64unpad nounce)
          $ BS.append "&x-nut-tag=" $ BS.take 22 $ enc64unpad tag





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
